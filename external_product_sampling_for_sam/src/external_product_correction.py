import argparse
import concurrent.futures
from math import ceil, log2

import dataclasses
import datetime
import pathlib
import json
import subprocess

import numpy as np
from scipy.optimize import curve_fit
from sklearn.ensemble import IsolationForest


# Command used to run Rust program responsible to perform sampling on external product.
BASH_COMMAND = "RUSTFLAGS=\"-C target-cpu=native -Awarnings\" cargo run --quiet --release -- --tot {} --id {} {}"

SECS_PER_HOUR = 3600
SECS_PER_MINUTES = 60

parser = argparse.ArgumentParser(description='Compute coefficient correction for external product')
parser.add_argument('chunks', type=int,
                    help='Total number of chunks the parameter grid is divided into.'
                         'Each chunk is run in a sub-process, to speed up processing make sure to'
                         ' have at least this number of CPU cores to allocate for this task')
parser.add_argument('--output-file', '-o', type=str, dest='output_filename',
                    default='correction_coefficients.json',
                    help='Output file containing correction coefficients, formatted as JSON'
                         ' (default: correction_coefficients.json)')
parser.add_argument('--file-pattern', '-f', type=str, dest='file_pattern',
                    default='*.acquisition_external_product*',
                    help='File pattern used to store result files from chunked sampling'
                         ' (default: "*.acquisition_external_product")')
parser.add_argument('--analysis-only', '-A', action= 'store_true', dest='analysis_only',
                    help='If this flag is set, no sampling will be done, it will only try to'
                         ' analyze existing results')
# parser.add_argument('sampling_args', nargs=argparse.REMAINDER,
#                     help='Arguments directly passed to sampling program, to get an exhaustive list'
#                          ' of options run command: `cargo run -- --help`')


@dataclasses.dataclass(init=False)
class SamplingLine:
    """
    Extract output variance parameter from a sampling result string.

    :param line: :class:`str` formatted as ``polynomial_size, glwe_dimension,
        decomposition_level_count, decomposition_base_log, input_variance, output_variance,
        predicted_variance``
    """
    parameters: list
    input_variance: float
    output_variance_exp: float
    output_variance_th: float

    def __init__(self, line: str):
        split_line = line.strip().split(", ")
        self.parameters = [float(x) for x in split_line[:4]]
        self.input_variance = float(split_line[5])
        self.output_variance_exp = float(split_line[6])
        self.output_variance_th = float(split_line[7])


def concatenate_result_files(pattern):
    """
    Concatenate result files into a single one. It uses a filename ``pattern`` to get all the files
    in the current working directory.

    :param pattern: filename pattern as :class:`str`
    :return: concatenated filename as :class:`pathlib.Path`
    """
    results_filepath = pathlib.Path('concatenated_sampling_results')
    with results_filepath.open('w') as results:
        for file in sorted(pathlib.Path('.').glob(pattern)):
            results.write(file.read_text())

    return results_filepath


def extract_from_acquisitions(filename):
    """
    Retrieve and parse data from sampling results.

    :param filename: sampling results filename as :class:`pathlib.Path`
    :return: :class:`tuple` of :class:`numpy.array`
    """
    parameters = []
    exp_output_variance = []
    th_output_variance = []
    input_variance = []

    with filename.open() as f:
        for line in f:
            try:
                sampled_line = SamplingLine(line)
            except Exception as err:
                # If an exception occurs when parsing a result line, we simply discard this one.
                print(f"Exception while parsing line (error: {err}, line: {line})")
                continue

            params = sampled_line.parameters
            exp_output_var = sampled_line.output_variance_exp
            th_output_var = sampled_line.output_variance_th
            input_var = sampled_line.input_variance

            if exp_output_var < 0.083:
                # * 2**128 to convert the torus variance into a modular variance
                params.append(th_output_var * 2 ** 128)
                parameters.append(params)
                exp_output_variance.append(exp_output_var * 2 ** 128)
                th_output_variance.append(th_output_var * 2 ** 128)
                input_variance.append(input_var * 2 ** 128)

    print(f"There is {len(parameters)} samples ...")

    return (np.array(parameters), np.array(exp_output_variance),
            np.array(th_output_variance), np.array(input_variance))


def get_input(filename, split_in_k=False):
    """
    :param filename: result filename as :class:`pathlib.Path`
    :return: :class:`tuple` of X and Y values
    """
    (parameters,
     exp_output_variance,
     th_output_variance,
     input_variance) = extract_from_acquisitions(filename)
    y_values = np.maximum(0., (exp_output_variance - input_variance))
    x_values = parameters

    mask = np.where(y_values > 0.)
    x_values, y_values = x_values[mask], y_values[mask]

    if split_in_k:
        x_values_splitted_in_k = []
        y_values_splitted_in_k = []

        for k in range(1, 7):
            mask = np.where(x_values[:,1] == k)[0]
            if len(np.bincount(mask)) > 1:
                x_values_splitted_in_k.append(x_values[mask, :])
                y_values_splitted_in_k.append(y_values[mask])
        return x_values_splitted_in_k, y_values_splitted_in_k
    else:
        return x_values, y_values


def get_input_without_outlier(filename, split_in_k=False):
    if split_in_k:
        x_values_splitted_in_k, y_values_splitted_in_k = get_input(filename, split_in_k=True)
        x_values_splitted_in_k_new, y_values_splitted_in_k_new = [], []
        for (x_values, y_values) in zip(x_values_splitted_in_k, y_values_splitted_in_k):
            x, y = remove_outlier(x_values, y_values)
            x_values_splitted_in_k_new.append(x)
            y_values_splitted_in_k_new.append(y)
        return x_values_splitted_in_k_new, y_values_splitted_in_k_new
    else:
        return remove_outlier(*get_input(filename))


def remove_outlier(x_values, y_values):
    """
    Remove outliers from a dataset using an isolation forest algorithm.

    :param x_values: values for the first dimension as :class:`list`
    :param y_values: values for the second dimension as :class:`list`
    :return: cleaned dataset as :class:`tuple` which element storing values a dimension in a
        :class:`list`
    """
    # identify outliers in the training dataset
    iso = IsolationForest(contamination=0.2)  # Contamination value obtained by experience
    yhat = iso.fit_predict(x_values)

    # select all rows that are not outliers
    mask = yhat != -1
    previous_size = len(x_values)
    x_values, y_values = x_values[mask, :], y_values[mask]
    new_size = len(x_values)
    print(f"Removing {previous_size - new_size} outliers ...")
    return x_values, y_values


def fft_noise(x, a, d):
    """
    Noise formula for FFTW.
    """
    N = x[:, 0]
    k = x[:, 1]
    level = x[:, 2]
    logbase = x[:, 3]
    theoretical_var = x[:, 4]
    return 2 ** a * (k + 1) * 2 ** 22 * (level * 2. ** (2 * logbase)) * N ** d + theoretical_var


def log_fft_noise(x, a, d):
    return np.log2(fft_noise(x, a, d))


def train(x_values, y_values):
    weights, _ = curve_fit(log_fft_noise, x_values, np.log2(y_values))
    return weights

def var_to_bit(variance):
    if variance <= 0:
        return np.nan
    else:
        return ceil(0.5 * log2(variance))


def test(x_values, y_values, weights):
    mse = 0.
    mse_without_correction = 0.
    for index in range(len(x_values)):
        params = np.array([x_values[index, :]])
        real_out = y_values[index]
        pred_out = max(fft_noise(params, *list(weights))[0], 0.000001)
        mse += (var_to_bit(real_out) - var_to_bit(pred_out)) ** 2
        mse_without_correction += (var_to_bit(real_out) - var_to_bit(params[0, 4])) ** 2
        # mse_without_correction += (var_to_bit(real_out) ) ** 2

    mse /= len(x_values)
    mse_without_correction /= len(x_values)
    return mse, mse_without_correction


def get_weights(filename, split_in_k=False):
    """
    Get weights from sampling results.

    :param filename: results filename as :class:`pathlib.Path`
    :return: :class:`dict` of weights formatted as ``{"a": <float>, "d": <float>}``
    """
    x_values_k_splitted_in_k, y_values_splitted_in_k = get_input_without_outlier(filename, split_in_k=split_in_k)

    if split_in_k:
        output_dict = {}
        for x_values, y_values in zip(x_values_k_splitted_in_k, y_values_splitted_in_k):
            print(f"--------- k = {int(x_values[0, 1])} ---------")
            weights = train(x_values, y_values)
            mse, mse_wo_correction = test(x_values, y_values, weights)
            print(f"> MSE: {mse}")
            print(f"> MSE w/o correction: {mse_wo_correction}")
            output_dict[int(x_values[0, 1])] = {"a": weights[0], "d": weights[1]}
        return output_dict

    else:
        x_values, y_values = x_values_k_splitted_in_k, y_values_splitted_in_k
        weights = train(x_values, y_values)
        mse, mse_wo_correction = test(x_values, y_values, weights)
        print(f"> MSE: {mse}")
        print(f"> MSE w/o correction: {mse_wo_correction}")
        return {"a": weights[0], "d": weights[1]}


def write_to_file(filename, obj):
    """
    Write the given ``obj``ect into a file formatted as JSON.

    :param filename: filename to write into as :class:`str`
    :param obj: object to write as JSON
    """
    filepath = pathlib.Path(filename)
    try:
        json.dump(obj, filepath.open('w'))
    except Exception as err:
        print(f"Exception occurred while writing to {filename}: {err}")
    else:
        print(f"Results written to {filename}")


def run_sampling_chunk(total_chunks, identity, input_args):
    """
    Run an external product sampling on a chunk of data as a subprocess.

    :param total_chunks: number of chunks the parameter is divided into
    :param identity: chunk identifier as :class:`int`
    :param input_args: arguments passed to sampling program
    """
    cmd = BASH_COMMAND.format(total_chunks, identity, input_args)
    start_time = datetime.datetime.now()
    print(f"External product sampling chunk #{identity} starting")

    process = subprocess.run(cmd, shell=True, capture_output=True)

    elapsed_time = (datetime.datetime.now() - start_time).total_seconds()
    hours = int(elapsed_time // SECS_PER_HOUR)
    minutes = int((elapsed_time % SECS_PER_HOUR) // SECS_PER_MINUTES)
    seconds = int(elapsed_time % SECS_PER_HOUR % SECS_PER_MINUTES)

    if process.returncode == 0:
        print(f"External product sampling chunk #{identity} successfully done in"
              f" {hours}:{minutes}:{seconds}")
    else:
        stderr = process.stderr.decode()
        stderr_formatted = f"STDERR: {stderr}" if stderr else ""
        print(f"External product sampling chunk #{identity} failed after"
              f" {hours}:{minutes}:{seconds}\n"
              f"STDOUT: {process.stdout.decode()}"
              f"{stderr_formatted}")


if __name__ == "__main__":
    args = parser.parse_args()
    if not args.analysis_only:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.chunks) as executor:
            futures = []
            for n in range(args.chunks):
                futures.append(executor.submit(run_sampling_chunk, args.chunks, n, " ".join(args.sampling_args)))

            # Wait for all sampling chunks to be completed.
            concurrent.futures.wait(futures)

    result_file = concatenate_result_files(args.file_pattern)
    # Extracting the weights and write it to a file
    write_to_file(args.output_filename, get_weights(result_file, split_in_k=True))
