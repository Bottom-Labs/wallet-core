use crate::curve_type::CurveType;
use crate::Result;
use parking_lot::RwLock;


#[derive(Clone)]
pub struct CoinInfo {
    pub coin: String,
    pub derivation_path: String,
    pub curve: CurveType,
    pub network: String,
    pub seg_wit: String,
}

lazy_static! {
    static ref COIN_INFOS : RwLock<Vec<CoinInfo>> = {
        let mut coin_infos = Vec::new();
        coin_infos.push(CoinInfo {
            coin: "BITCOIN".to_string(),
            derivation_path: "m/44'/0'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "NONE".to_string(),
        });

        RwLock::new(coin_infos)
    };
}

pub fn coin_info_from_param(chain_type: &str, network: &str, seg_wit: &str) -> Result<CoinInfo> {
    let coin_infos = COIN_INFOS.read();
    let mut coins = coin_infos
        .iter()
        .filter(|x| {
            x.coin.as_str() == chain_type
            && (x.network.as_str() == network || network.is_empty())
            && (x.seg_wit.as_str() == seg_wit || seg_wit.is_empty())
        })
        .map(|x| x.clone())
        .collect::<Vec<CoinInfo>>();
    if coins.is_empty() {
        Err(format_err!("unsupported chain"))
    } else {
        Ok(coins.pop().expect("coin info from param"))
    }
}





