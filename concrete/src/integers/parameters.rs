use concrete_integer::{CrtCiphertext, CrtClientKey, RadixCiphertext, RadixClientKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Parameters for 'radix' decomposition
///
/// Radix decomposition works by using multiple shortint blocks
/// with the same parameters to represent an integer.
///
/// For example, by taking 4 blocks with parameters
/// for 2bits shortints, with have a 4 * 2 = 8 bit integer.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug)]
pub struct RadixParameters {
    pub block_parameters: concrete_shortint::Parameters,
    pub num_block: usize,
    pub wopbs_block_parameters: concrete_shortint::Parameters,
}

/// Parameters for 'CRT' decomposition
///
/// (Chinese Remainder Theorem)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct CrtParameters {
    pub block_parameters: concrete_shortint::Parameters,
    pub moduli: Vec<u64>,
    pub wopbs_block_parameters: concrete_shortint::Parameters,
}

pub trait PrivateIntegerKey {
    type Ciphertext;

    fn encrypt(&self, value: u64) -> Self::Ciphertext;

    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> u64;
}

/// Meant to be implemented on the inner server key
/// eg the concrete_integer::ServerKey
pub trait EvaluationIntegerKey<ClientKey> {
    fn new(client_key: &ClientKey) -> Self;

    fn new_wopbs_key(
        client_key: &ClientKey,
        server_key: &Self,
        wopbs_block_parameters: concrete_shortint::Parameters,
    ) -> concrete_integer::wopbs::WopbsKey;
}

pub trait FromParameters<P> {
    fn from_parameters(parameters: P) -> Self;
}

impl<P> FromParameters<P> for concrete_integer::RadixClientKey
where
    P: Into<RadixParameters>,
{
    fn from_parameters(parameters: P) -> Self {
        let params = parameters.into();
        #[cfg(feature = "internal-keycache")]
        {
            use concrete_integer::keycache::KEY_CACHE;
            let key = KEY_CACHE.get_from_params(params.block_parameters).0;
            concrete_integer::RadixClientKey::from((key, params.num_block))
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            concrete_integer::RadixClientKey::new(params.block_parameters, params.num_block)
        }
    }
}

impl<P> FromParameters<P> for concrete_integer::CrtClientKey
where
    P: Into<CrtParameters>,
{
    fn from_parameters(parameters: P) -> Self {
        let params = parameters.into();
        #[cfg(feature = "internal-keycache")]
        {
            use concrete_integer::keycache::KEY_CACHE;
            let key = KEY_CACHE.get_from_params(params.block_parameters).0;
            concrete_integer::CrtClientKey::from((key, params.moduli))
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            concrete_integer::CrtClientKey::new(params.block_parameters, params.moduli)
        }
    }
}

/// Trait to mark parameters type for integers
pub trait IntegerParameter: Clone {
    /// The Id allows to differentiate the different parameters
    /// as well as retrieving the corresponding client key and server key
    type Id: Copy;
    #[cfg(feature = "serde")]
    type InnerCiphertext: serde::Serialize + for<'de> serde::Deserialize<'de>;
    #[cfg(not(feature = "serde"))]
    type InnerCiphertext;
    type InnerClientKey: FromParameters<Self>
        + PrivateIntegerKey<Ciphertext = Self::InnerCiphertext>;
    type InnerServerKey;

    fn wopbs_block_parameters(&self) -> concrete_shortint::Parameters;

    fn block_parameters(&self) -> concrete_shortint::Parameters;
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct RadixRepresentation;
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct CrtRepresentation;

/// Trait to mark parameters type for static integers
///
/// Static means the integer types with parameters provided by
/// the crate, so parameters for which we know the number of
/// bits the represent.
pub trait StaticIntegerParameter: IntegerParameter {
    type Representation: Default + Eq;

    const MESSAGE_BITS: usize;
}

pub trait StaticRadixParameter:
    StaticIntegerParameter<Representation = RadixRepresentation>
where
    Self: IntegerParameter<
        InnerClientKey = RadixClientKey,
        InnerServerKey = concrete_integer::ServerKey,
        InnerCiphertext = RadixCiphertext,
    >,
{
}
pub trait StaticCrtParameter: StaticIntegerParameter<Representation = CrtRepresentation>
where
    Self: IntegerParameter<
        InnerClientKey = CrtClientKey,
        InnerServerKey = concrete_integer::ServerKey,
        InnerCiphertext = CrtCiphertext,
    >,
{
}
