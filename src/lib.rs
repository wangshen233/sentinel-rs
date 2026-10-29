//! 库入口：模块声明 + C ABI 导出（供 Python ctypes / 其它语言调用 DLL）。

pub mod env;
pub mod flow;
pub mod mint;
pub mod so;
pub mod token;
pub mod value;
pub mod vm;

mod ffi;

pub use ffi::{
    srs_free, srs_mint_so, srs_mint_t, srs_register, srs_requirements_token, srs_version,
};
