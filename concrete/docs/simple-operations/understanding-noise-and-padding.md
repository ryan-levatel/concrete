# Understanding noise and padding

In FHE, there are two types of operations that can be applied to ciphertexts:

* **leveled operations**, which are faster but increase the noise in the ciphertext
* **bootstrapped operations**, which are slower but reduce the noise in the ciphertext

This section explains the concept of **noise** and **padding** in ciphertexts, which are core to how Concrete enables efficient homomorphic operations.

## Noise

\(R\)LWE requires random noise to be added to the plaintext at encryption time to be secure. The ''size'' of the noise \(or, more precisely, $$\log_2 (std dev)$$\) is a security parameter, so that larger is the noise, the more secure is the encryption.

In Concrete, the noise is encoded in the least significants bits of a ciphertext. Each leveled computation will increase the noise, and thus if too many computations are done, the noise will eventually overflow onto the significant data bits and lead to an incorrect result.

The figure below illustrates this problem in case of an addition, where an extra bit of noise is incurred as a result.

![Noise overtaking on the plaintexts after homomorphic addition.  Most Significant bits are on the left.](../_static/fig1.png)

Concrete enables managing noise in multiple ways:

* by emitting a warning when the ciphertext has accumulated too much noise.
* by enabling to chose the precision of the encoding to allow for more empty bits between the noise and the message.
* by performing a bootstrapping operation to reset the noise to a nominal value.

## Padding

Since encoded values have a fixed precision, operating on them can sometime produce results that are outside the original interval. To avoid losing precision or wrapping around the interval, Concrete enables storing the additional bits by defining bits of **padding** on the most significant bits. Padding bits are defined as part of the encoder.

As an example, consider adding two ciphertexts. Adding two values could en up outside the range of either encoders, and thus necessitate a carry, which would then be carried onto the first padding bit. In the figure below, each plaintext over 32 bits has one bit of padding on its left \(i.e., the most significant bit\). After the addition, the padding bit is no longer available, as it has been used in order for the carry. This is referred to as **consuming** bits of padding. Since no padding is left, there is no guarantee that additional additions would yield correct results.

![](../_static/fig2.png)



Concrete enables managing padding in multiple ways:

* via methods that enable determining at runtime how many bits of padding are left.
* by defining an encoder with enough bits of padding.
* by performing a bootstrapping operation that frees up bits of padding.

{% hint style="warning" %}
Make sure to provision enough bits of padding for your program to run correctly, it will be more efficient than bootstrapping too often.
{% endhint %}
