use clap::Parser;
use concrete_commons::dispersion::{DispersionParameter, StandardDev, Variance};
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use concrete_core::prelude::{
    AbstractEngine, CoreEngine, FourierGgswCiphertext64, GlweCiphertext64,
};
use concrete_core_fixture::fixture::{
    Fixture, GlweCiphertextGgswCiphertextExternalProductFixture,
    GlweCiphertextGgswCiphertextExternalProductParameters,
};
use concrete_core_fixture::generation::{Maker, Precision64};
use concrete_core_fixture::{Repetitions, SampleSize};
use itertools::iproduct;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::fs::OpenOptions;
use std::io::Write;
use {concrete_npe, f64, rand};

pub const DEBUG: bool = false;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Total number of threads.
    #[clap(long, short)]
    tot: usize,
    /// Current Thread ID
    #[clap(long, short)]
    id: usize,
    /// Number of time a test is repeated for a single set of parameter.
    /// This indicates the number of different keys since, at each repetition, we re-sample
    /// everything
    #[clap(long, short, default_value_t = 15)]
    repetitions: usize,
    /// The size of the sample per key
    #[clap(long, short = 'S', default_value_t = 40)]
    sample_size: usize,
    /// Step used for testing levels beyond 20in hypercube.
    /// Example: with a step of 3, tested levels tested would be: 1 through 20 then 21, 24, 27, etc
    #[clap(long, short = 's', default_value_t = 1)]
    steps: usize,
    /// Set value of the bit for GGSW
    #[clap(long, short, default_value_t = 1)]
    ggsw_value: usize,
    /// Provide a random bit for GGSW on demand
    #[clap(long, short = 'R', conflicts_with = "ggsw-value")]
    random_ggsw: bool,
}

fn variance_to_stddev(var: Variance) -> StandardDev {
    StandardDev::from_standard_dev(var.get_standard_dev())
}

fn write_to_file(
    params: &GlweCiphertextGgswCiphertextExternalProductParameters,
    input_stddev: StandardDev,
    output_stddev: StandardDev,
    pred_stddev: StandardDev,
    id: usize,
) {
    let data_to_save = format!(
        "{}, {}, {}, {}, {}, {}, {}, {}\n",
        params.polynomial_size.0,
        params.glwe_dimension.0,
        params.decomposition_level_count.0,
        params.decomposition_base_log.0,
        params.ggsw_encrypted_value,
        input_stddev.get_variance(),
        output_stddev.get_variance(),
        pred_stddev.get_variance()
    );

    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open(format!("{}.acquisition_external_product", id))
    {
        Err(why) => panic!("{}", why),
        Ok(file) => file,
    };
    file.write(data_to_save.as_bytes()).unwrap();
}

fn write_to_file_debug(
    params: &GlweCiphertextGgswCiphertextExternalProductParameters,
    errors: &[f64],
    rep: usize,
) {
    let filename = format!(
        "samples/{}.{}-{}-{}-{}.extprod.samples",
        rep,
        params.polynomial_size.0,
        params.glwe_dimension.0,
        params.decomposition_level_count.0,
        params.decomposition_base_log.0,
    );
    // let data_to_save = format!(
    //     "{}, {}, {}, {}, {}, {}, {}, ",
    //     params.polynomial_size.0,
    //     params.glwe_dimension.0,
    //     params.decomposition_level_count.0,
    //     params.decomposition_base_log.0,
    //     input_stddev.get_variance(),
    //     output_stddev.get_variance(),
    //     pred_stddev.get_variance(),
    // );
    // file.write(data_to_save.as_bytes()).unwrap();

    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
    {
        Err(why) => panic!("{}", why),
        Ok(file) => file,
    };

    if errors.len() > 0 {
        let errors: String = errors
            .iter()
            .map(|x| x.to_string()) // format!("{}", x))
            .collect::<Vec<String>>()
            .join(", ");
        file.write(errors.as_bytes()).unwrap();
    }
}
#[derive(Debug)]
struct NotABit(u64);

fn minimal_variance_for_security_64(k: GlweDimension, size: PolynomialSize) -> f64 {
    f64::max(
        f64::powf(
            2.,
            -2. * 0.026374888765705498 * k.0 as f64 * size.0 as f64 + 2. * 2.012143923330495,
        ),
        f64::powi(2., -(2 * 64 - 2 * 2)),
    )
}

fn mean(data: &[f64]) -> Option<f64> {
    // adapted from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    let sum = data.iter().sum::<f64>() as f64;
    let count = data.len();

    match count {
        positive if positive > 0 => Some(sum / count as f64),
        _ => None,
    }
}

fn std_deviation(data: &[f64]) -> Option<StandardDev> {
    // from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    // replacing the mean by 0. as we theoretically know it
    match (mean(data), data.len()) {
        (Some(_data_mean), count) if count > 0 => {
            let variance = data
                .iter()
                .map(|value| {
                    let diff = 0. - (*value as f64);

                    diff * diff
                })
                .sum::<f64>()
                / count as f64;

            Some(StandardDev::from_modular_standard_dev::<u64>(
                variance.sqrt(),
            ))
        }
        _ => None,
    }
}

fn compute_error(errs: &mut [f64], output: Vec<u64>, input: Vec<u64>, bit: u64) {
    match bit {
        1 => {
            for (out, (inp, err)) in output.iter().zip(input.iter().zip(errs.iter_mut())) {
                *err = (out.wrapping_sub(*inp)) as i64 as f64;
            }
        }
        0 => {
            for (out, err) in output.iter().zip(errs.iter_mut()) {
                *err = *out as i64 as f64;
            }
        }
        _ => panic!("Not a bit: {:?}", NotABit(bit)),
    }
}

#[derive(Debug)]
enum Parameter {
    Singleton(usize),
    BaseLevel { base: usize, level: usize },
}

impl Clone for Parameter {
    fn clone(&self) -> Self {
        match self {
            Parameter::Singleton(val) => Parameter::Singleton(*val),
            Parameter::BaseLevel { base, level } => Parameter::BaseLevel {
                base: *base,
                level: *level,
            },
        }
    }
}

impl Parameter {
    pub fn get_singleton(&self) -> usize {
        match self {
            Parameter::Singleton(val) => *val,
            Parameter::BaseLevel { base: _, level: _ } => panic!(),
        }
    }

    pub fn get_level(&self) -> usize {
        match self {
            Parameter::Singleton(_) => panic!(),
            Parameter::BaseLevel { base: _, level } => *level,
        }
    }
    pub fn get_base(&self) -> usize {
        match self {
            Parameter::Singleton(val) => panic!(),
            Parameter::BaseLevel { base, level: _ } => *base,
        }
    }
}

fn compute_nb_of_b_l(bases: &[usize], levels: &[usize]) -> usize {
    let mut compt = 0;
    for (b, l) in bases.iter().zip(levels.iter()) {
        if b * l <= 53 {
            compt += 1;
        }
    }
    compt
}

fn filter_b_l(bases: &[usize], levels: &[usize]) -> Vec<Parameter> {
    let mut bases_levels = vec![];
    for (b, l) in iproduct!(bases, levels) {
        if b * l <= 53 {
            bases_levels.push(Parameter::BaseLevel {
                base: *b,
                level: *l,
            });
        }
    }
    bases_levels
}

fn main() {
    let args = Args::parse();
    let tot = args.tot;
    let id = args.id;
    let total_repetitions = Repetitions(args.repetitions);
    let base_sample_size = args.sample_size;
    let ggsw_value: Option<usize> = match args.random_ggsw {
        true => None,
        false => Some(args.ggsw_value),
    };

    // Fixture Init
    let mut maker = Maker::default();
    let mut engine = CoreEngine::new().unwrap();
    type Precision = Precision64;

    // Parameter Grid
    let polynomial_sizes = vec![
        Parameter::Singleton(1 << 8),
        Parameter::Singleton(1 << 9),
        Parameter::Singleton(1 << 10),
        Parameter::Singleton(1 << 11),
        Parameter::Singleton(1 << 12),
        Parameter::Singleton(1 << 13),
        Parameter::Singleton(1 << 14),
    ];
    let max_polynomial_size = 1 << 14;
    let glwe_dimensions = vec![
        Parameter::Singleton(1),
        Parameter::Singleton(2),
        Parameter::Singleton(3),
        Parameter::Singleton(4),
        Parameter::Singleton(5),
        Parameter::Singleton(6),
    ];

    let mut base_logs = vec![1usize; 64];
    for b in 1..65 {
        base_logs[b - 1] = b;
    }
    let mut levels = (1..21).collect::<Vec<_>>();
    let mut stepped_levels = (21..65).step_by(args.steps).collect::<Vec<_>>();
    levels.append(&mut stepped_levels);
    let bases_levels = filter_b_l(&base_logs, &levels);

    let hypercube = iproduct!(glwe_dimensions, bases_levels, polynomial_sizes);
    let mut hypercube: Vec<(Parameter, Parameter, Parameter)> = hypercube.collect();
    let seed = [0; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    hypercube.shuffle(&mut rng);
    // only keeping part of the hypercube
    let chunk_size = hypercube.len() / tot;
    println!(
        "-> Thread #{} computing chunk [{}..{}]",
        id,
        id * chunk_size,
        (id + 1) * chunk_size
    );

    for (k, b_l, size) in hypercube[id * chunk_size..(id + 1) * chunk_size].iter() {
        let sample_size = SampleSize(base_sample_size * max_polynomial_size / size.get_singleton());
        let glwe_dimension = GlweDimension(k.get_singleton());
        let poly_size = PolynomialSize(size.get_singleton());
        let dec_level_count = DecompositionLevelCount(b_l.get_level());
        let dec_base_log = DecompositionBaseLog(b_l.get_base());
        let ggsw_noise =
            Variance::from_variance(minimal_variance_for_security_64(glwe_dimension, poly_size));
        let glwe_noise =
            Variance::from_variance(minimal_variance_for_security_64(glwe_dimension, poly_size));

        if glwe_dimension.0 * poly_size.0 <= 1 << 14 {
            let mut parameters = GlweCiphertextGgswCiphertextExternalProductParameters {
                ggsw_noise,
                glwe_noise,
                glwe_dimension,
                ggsw_encrypted_value: 0,
                polynomial_size: poly_size,
                decomposition_base_log: dec_base_log,
                decomposition_level_count: dec_level_count,
            };

            let noise_prediction = concrete_npe::estimate_external_product_noise_with_binary_ggsw::<
                u64,
                _,
                _,
                BinaryKeyKind,
            >(
                poly_size,
                glwe_dimension,
                glwe_noise,
                glwe_noise,
                dec_base_log,
                dec_level_count,
            );

            let mut errors = vec![0.; sample_size.0 * size.get_singleton() * total_repetitions.0];

            if noise_prediction.get_variance() < 1. / 12. {
                for (_, errs) in (0..total_repetitions.0)
                    .zip(errors.chunks_mut(sample_size.0 * size.get_singleton()))
                {
                    parameters.ggsw_encrypted_value = match ggsw_value {
                        Some(value) => value,
                        // GGSW value is randomly generated here so that other functions can retrieve
                        // its value
                        None => rand::thread_rng().gen_range(0, 2),
                    };

                    let repetitions =
                        <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
                            Precision,
                            CoreEngine,
                            (GlweCiphertext64, FourierGgswCiphertext64, GlweCiphertext64),
                        >>::generate_random_repetition_prototypes(
                            &parameters, &mut maker
                        );
                    let outputs = <GlweCiphertextGgswCiphertextExternalProductFixture as Fixture<
                        Precision,
                        CoreEngine,
                        (GlweCiphertext64, FourierGgswCiphertext64, GlweCiphertext64),
                    >>::sample(
                        &mut maker,
                        &mut engine,
                        &parameters,
                        &repetitions,
                        sample_size,
                    );
                    let (raw_inputs, output): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
                    let raw_input_plaintext_vector =
                        raw_inputs.into_iter().flatten().collect::<Vec<_>>();
                    let output_plaintext_vector = output.into_iter().flatten().collect::<Vec<_>>();

                    // errors[rep * sample_size.0 * *size..(rep + 1) * sample_size.0 * *size] =
                    compute_error(
                        errs,
                        output_plaintext_vector,
                        raw_input_plaintext_vector,
                        parameters.ggsw_encrypted_value as u64,
                    );
                }
                let _mean_err = mean(&errors).unwrap();
                let std_err = std_deviation(&errors).unwrap();
                if DEBUG {
                    write_to_file_debug(&parameters, &errors, id);
                } else {
                    write_to_file(
                        &parameters,
                        variance_to_stddev(glwe_noise),
                        std_err,
                        variance_to_stddev(noise_prediction),
                        id,
                    );
                }
            } else {
                if DEBUG {
                    write_to_file_debug(&parameters, &vec![], 0usize)
                } else {
                    write_to_file(
                        &parameters,
                        variance_to_stddev(glwe_noise),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        id,
                    )
                }
            }
        }
        // }
    }
}
