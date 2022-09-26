use crate::parameters::parameters_wopbs::*;
use crate::parameters::parameters_wopbs_message_carry::*;
use crate::parameters::parameters_wopbs_prime_moduli::*;
use crate::parameters::*;
use crate::treepbs::TreepbsKey;
use crate::wopbs::WopbsKey;
use crate::{ClientKey, ServerKey};
use concrete_utils::keycache::{
    FileStorage, KeyCache as TKeyCache, NamedParam, SharedKey as GenericSharedKey,
};
use concrete_utils::named_params_impl;
use lazy_static::*;

impl NamedParam for Parameters {
    fn name(&self) -> String {
        named_params_impl!(
            self == (
                PARAM_MESSAGE_1_CARRY_1,
                PARAM_MESSAGE_1_CARRY_2,
                PARAM_MESSAGE_1_CARRY_3,
                PARAM_MESSAGE_1_CARRY_4,
                PARAM_MESSAGE_1_CARRY_5,
                PARAM_MESSAGE_1_CARRY_6,
                PARAM_MESSAGE_1_CARRY_7,
                PARAM_MESSAGE_2_CARRY_1,
                PARAM_MESSAGE_2_CARRY_2,
                PARAM_MESSAGE_2_CARRY_3,
                PARAM_MESSAGE_2_CARRY_4,
                PARAM_MESSAGE_2_CARRY_5,
                PARAM_MESSAGE_2_CARRY_6,
                PARAM_MESSAGE_3_CARRY_1,
                PARAM_MESSAGE_3_CARRY_2,
                PARAM_MESSAGE_3_CARRY_3,
                PARAM_MESSAGE_3_CARRY_4,
                PARAM_MESSAGE_3_CARRY_5,
                PARAM_MESSAGE_4_CARRY_1,
                PARAM_MESSAGE_4_CARRY_2,
                PARAM_MESSAGE_4_CARRY_3,
                PARAM_MESSAGE_4_CARRY_4,
                PARAM_MESSAGE_5_CARRY_1,
                PARAM_MESSAGE_5_CARRY_2,
                PARAM_MESSAGE_5_CARRY_3,
                PARAM_MESSAGE_6_CARRY_1,
                PARAM_MESSAGE_6_CARRY_2,
                PARAM_MESSAGE_7_CARRY_1,
                WOPBS_PARAM_MESSAGE_1_NORM2_2,
                WOPBS_PARAM_MESSAGE_1_NORM2_4,
                WOPBS_PARAM_MESSAGE_1_NORM2_6,
                WOPBS_PARAM_MESSAGE_1_NORM2_8,
                WOPBS_PARAM_MESSAGE_2_NORM2_2,
                WOPBS_PARAM_MESSAGE_2_NORM2_4,
                WOPBS_PARAM_MESSAGE_2_NORM2_6,
                WOPBS_PARAM_MESSAGE_2_NORM2_8,
                WOPBS_PARAM_MESSAGE_3_NORM2_2,
                WOPBS_PARAM_MESSAGE_3_NORM2_4,
                WOPBS_PARAM_MESSAGE_3_NORM2_6,
                WOPBS_PARAM_MESSAGE_3_NORM2_8,
                WOPBS_PARAM_MESSAGE_4_NORM2_2,
                WOPBS_PARAM_MESSAGE_4_NORM2_4,
                WOPBS_PARAM_MESSAGE_4_NORM2_6,
                WOPBS_PARAM_MESSAGE_4_NORM2_8,
                WOPBS_PARAM_MESSAGE_5_NORM2_2,
                WOPBS_PARAM_MESSAGE_5_NORM2_4,
                WOPBS_PARAM_MESSAGE_5_NORM2_6,
                WOPBS_PARAM_MESSAGE_5_NORM2_8,
                WOPBS_PARAM_MESSAGE_6_NORM2_2,
                WOPBS_PARAM_MESSAGE_6_NORM2_4,
                WOPBS_PARAM_MESSAGE_6_NORM2_6,
                WOPBS_PARAM_MESSAGE_6_NORM2_8,
                WOPBS_PARAM_MESSAGE_7_NORM2_2,
                WOPBS_PARAM_MESSAGE_7_NORM2_4,
                WOPBS_PARAM_MESSAGE_7_NORM2_6,
                WOPBS_PARAM_MESSAGE_7_NORM2_8,
                WOPBS_PARAM_MESSAGE_8_NORM2_2,
                WOPBS_PARAM_MESSAGE_8_NORM2_4,
                WOPBS_PARAM_MESSAGE_8_NORM2_5,
                WOPBS_PARAM_MESSAGE_8_NORM2_6,
                WOPBS_PARAM_MESSAGE_1_CARRY_0,
                WOPBS_PARAM_MESSAGE_1_CARRY_1,
                WOPBS_PARAM_MESSAGE_1_CARRY_2,
                WOPBS_PARAM_MESSAGE_1_CARRY_3,
                WOPBS_PARAM_MESSAGE_1_CARRY_4,
                WOPBS_PARAM_MESSAGE_1_CARRY_5,
                WOPBS_PARAM_MESSAGE_1_CARRY_6,
                WOPBS_PARAM_MESSAGE_1_CARRY_7,
                WOPBS_PARAM_MESSAGE_2_CARRY_0,
                WOPBS_PARAM_MESSAGE_2_CARRY_1,
                WOPBS_PARAM_MESSAGE_2_CARRY_2,
                WOPBS_PARAM_MESSAGE_2_CARRY_3,
                WOPBS_PARAM_MESSAGE_2_CARRY_4,
                WOPBS_PARAM_MESSAGE_2_CARRY_5,
                WOPBS_PARAM_MESSAGE_2_CARRY_6,
                WOPBS_PARAM_MESSAGE_3_CARRY_0,
                WOPBS_PARAM_MESSAGE_3_CARRY_1,
                WOPBS_PARAM_MESSAGE_3_CARRY_2,
                WOPBS_PARAM_MESSAGE_3_CARRY_3,
                WOPBS_PARAM_MESSAGE_3_CARRY_4,
                WOPBS_PARAM_MESSAGE_3_CARRY_5,
                WOPBS_PARAM_MESSAGE_4_CARRY_0,
                WOPBS_PARAM_MESSAGE_4_CARRY_1,
                WOPBS_PARAM_MESSAGE_4_CARRY_2,
                WOPBS_PARAM_MESSAGE_4_CARRY_3,
                WOPBS_PARAM_MESSAGE_4_CARRY_4,
                WOPBS_PARAM_MESSAGE_5_CARRY_0,
                WOPBS_PARAM_MESSAGE_5_CARRY_1,
                WOPBS_PARAM_MESSAGE_5_CARRY_2,
                WOPBS_PARAM_MESSAGE_5_CARRY_3,
                WOPBS_PARAM_MESSAGE_6_CARRY_0,
                WOPBS_PARAM_MESSAGE_6_CARRY_1,
                WOPBS_PARAM_MESSAGE_6_CARRY_2,
                WOPBS_PARAM_MESSAGE_7_CARRY_0,
                WOPBS_PARAM_MESSAGE_7_CARRY_1,
                WOPBS_PARAM_MESSAGE_8_CARRY_0,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_7,
                WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_8,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_2,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_3,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_4,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_5,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_6,
                WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_7,
                PARAM_NAWAK
            )
        );
    }
}

impl From<Parameters> for (ClientKey, ServerKey) {
    fn from(param: Parameters) -> Self {
        let cks = ClientKey::new(param);
        let sks = ServerKey::new(&cks);
        (cks, sks)
    }
}

pub struct Keycache {
    inner: TKeyCache<Parameters, (ClientKey, ServerKey), FileStorage>,
}

impl Default for Keycache {
    fn default() -> Self {
        Self {
            inner: TKeyCache::new(FileStorage::new(
                "../keys/shortint/client_server".to_string(),
            )),
        }
    }
}

pub struct SharedKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
}

pub struct SharedWopbsKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
    wopbs: GenericSharedKey<WopbsKey>,
}

pub struct SharedTreePbsKey {
    inner: GenericSharedKey<TreepbsKey>,
}

impl SharedKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
}

impl SharedWopbsKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
    pub fn wopbs_key(&self) -> &WopbsKey {
        &self.wopbs
    }
}

impl SharedTreePbsKey {
    pub fn treepbs_key(&self) -> &TreepbsKey {
        &self.inner
    }
}

impl Keycache {
    pub fn get_from_param(&self, param: Parameters) -> SharedKey {
        SharedKey {
            inner: self.inner.get(param),
        }
    }
}

impl From<Parameters> for WopbsKey {
    fn from(param: Parameters) -> Self {
        // use with_key to avoid doing a temporary cloning
        KEY_CACHE
            .inner
            .with_key(param, |keys| WopbsKey::new_wopbs_key(&keys.0, &keys.1))
    }
}

pub struct KeycacheTreePpbs {
    inner: TKeyCache<Parameters, TreepbsKey, FileStorage>,
}

/// This impl is a workaround / cheat
/// maybe we should find a better way
impl From<Parameters> for TreepbsKey {
    fn from(params: Parameters) -> Self {
        let shared_key = KEY_CACHE.get_from_param(params);
        Self::new_tree_key(shared_key.client_key())
    }
}

impl Default for KeycacheTreePpbs {
    fn default() -> Self {
        let persistent_storage = FileStorage::new("../keys/shortint/treepbs".to_string());

        Self {
            inner: TKeyCache::new(persistent_storage),
        }
    }
}

impl KeycacheTreePpbs {
    pub fn get_from_param(&self, param: Parameters) -> SharedTreePbsKey {
        SharedTreePbsKey {
            inner: self.inner.get(param),
        }
    }
}

/// The KeyCache struct for shortint.
///
/// You should not create an instance yourself,
/// but rather use the global variable defined: [KEY_CACHE_WOPBS]
pub struct KeycacheWopbsV0 {
    inner: TKeyCache<Parameters, WopbsKey, FileStorage>,
}

impl Default for KeycacheWopbsV0 {
    fn default() -> Self {
        Self {
            inner: TKeyCache::new(FileStorage::new("../keys/shortint/wopbs_v0".to_string())),
        }
    }
}

impl KeycacheWopbsV0 {
    pub fn get_from_param(&self, param: Parameters) -> SharedWopbsKey {
        let key = KEY_CACHE.get_from_param(param);
        let wk = self.inner.get(param);
        SharedWopbsKey {
            inner: key.inner,
            wopbs: wk,
        }
    }
}

lazy_static! {
    pub static ref KEY_CACHE: Keycache = Default::default();
    pub static ref KEY_CACHE_WOPBS: KeycacheWopbsV0 = Default::default();
    pub static ref KEY_CACHE_TREEPBS: KeycacheTreePpbs = Default::default();
}
