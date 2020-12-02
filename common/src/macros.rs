
pub mod macros {
    #[macro_export]
    macro_rules! ensure {
        ($cond:expr, $e:expr) => {
            if !($cond) {
                return Err($e.into());
            }
        }
    }
}