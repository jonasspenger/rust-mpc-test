use curv::elliptic::curves::ed25519::{FE, GE};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use itertools::multizip;
use sha2::{Digest, Sha256};
use rand;

// Implementation of semi-honest OT protocol Protocol 5.1
// https://eprint.iacr.org/2013/552
// @misc{cryptoeprint:2013:552,
// author = {Gilad Asharov and Yehuda Lindell and Thomas Schneider and Michael Zohner},
// title = {More Efficient Oblivious Transfer and Extensions for Faster Secure Computation},
// howpublished = {Cryptology ePrint Archive, Report 2013/552},
// year = {2013},
// note = {\url{https://eprint.iacr.org/2013/552}},
// }

pub fn first_round(sigma: u8) -> (FE, GE, GE) {
    assert!(sigma == 0 || sigma == 1);
    let g = GE::generator();
    let a_i = FE::new_random();
    let h_i = g * FE::new_random(); // TODO: sample random element
    let (h_0, h_1) = if sigma == 0 {
        let h_0 = g * a_i;
        let h_1 = h_i;
        (h_0, h_1)
    } else {
        let h_0 = h_i;
        let h_1 = g * a_i;
        (h_0, h_1)
    };
    (a_i, h_0, h_1)
}

pub fn first_round_batch(sigma_vec: Vec<u8>) -> (Vec<FE>, Vec<GE>, Vec<GE>) {
    let tmp_vec: Vec<(FE, GE, GE)> = sigma_vec.iter().map(|&x| first_round(x)).collect();
    let a_i_vec = tmp_vec.iter().map(|x|{x.0}).collect();
    let h_0_vec = tmp_vec.iter().map(|x|{x.1}).collect();
    let h_1_vec = tmp_vec.iter().map(|x|{x.2}).collect();
    (a_i_vec, h_0_vec, h_1_vec)
}

fn h(x: Vec<u8>) -> Vec<u8> {
    let mut sh = Sha256::new();
    sh.update(x);
    sh.finalize().as_slice().to_vec()
}

fn xor(x: &Vec<u8>, y: &Vec<u8>) -> Vec<u8> {
    x.iter().zip(y.iter()).map(|(&a, &b)| a ^ b).collect()
}

pub fn second_round(x_0: &Vec<u8>, h_0: GE, x_1: &Vec<u8>, h_1: GE) -> (GE, Vec<u8>, Vec<u8>) {
    let g = GE::generator();
    let r = FE::new_random();
    let u = g * r;
    let k_0 = h_0 * r;
    let k_1 = h_1 * r;
    let kdf_0 = h(k_0.get_element().to_bytes().to_vec());
    let v_0 = xor(&kdf_0, &x_0);
    let kdf_1 = h(k_1.get_element().to_bytes().to_vec());
    let v_1 = xor(&kdf_1, &x_1);
    (u, v_0, v_1)
}

pub fn second_round_batch(
    x_0_vec: Vec<Vec<u8>>,
    h_0_vec: Vec<GE>,
    x_1_vec: Vec<Vec<u8>>,
    h_1_vec: Vec<GE>,
) -> (Vec<GE>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let tmp_vec: Vec<(GE, Vec<u8>, Vec<u8>)> = multizip((x_0_vec, h_0_vec, x_1_vec, h_1_vec))
        .map(|(x_0, h_0, x_1, h_1)| second_round(&x_0, h_0, &x_1, h_1))
        .collect();
    let u_vec = tmp_vec.iter().map(|x|{x.0}).collect();
    let v_0_vec = tmp_vec.iter().map(|x|{x.1.clone()}).collect();
    let v_1_vec = tmp_vec.iter().map(|x|{x.2.clone()}).collect();
    (u_vec, v_0_vec, v_1_vec)
}

pub fn output_computation(sigma: u8, a_i: FE, u: GE, v_0: Vec<u8>, v_1: Vec<u8>) -> Vec<u8> {
    assert!(sigma == 0 || sigma == 1);
    let v_sigma = if sigma == 0 { v_0 } else { v_1 };
    let k_sigma = u * a_i;
    let kdf_sigma = h(k_sigma.get_element().to_bytes().to_vec());
    let x_sigma = xor(&v_sigma, &kdf_sigma);
    x_sigma
}

pub fn output_computation_batch(
    sigma_vec: Vec<u8>,
    a_i_vec: Vec<FE>,
    u_vec: Vec<GE>,
    v_0_vec: Vec<Vec<u8>>,
    v_1_vec: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    multizip((sigma_vec, a_i_vec, u_vec, v_0_vec, v_1_vec))
        .map(|(sigma, a_i, u, v_0, v_1)| output_computation(sigma, a_i, u, v_0, v_1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semi_honest_ot() {
        let sigma = 0;
        let x_0 = FE::new_random().get_element().to_bytes().to_vec();
        let x_1 = FE::new_random().get_element().to_bytes().to_vec();

        let (a_i, h_0, h_1) = first_round(sigma);
        let (u, v_0, v_1) = second_round(&x_0, h_0, &x_1, h_1);
        let x = output_computation(sigma, a_i, u, v_0, v_1);

        assert_eq!(x_0, x);

        let sigma = 1;
        let x_0 = FE::new_random().get_element().to_bytes().to_vec();
        let x_1 = FE::new_random().get_element().to_bytes().to_vec();

        let (a_i, h_0, h_1) = first_round(sigma);
        let (u, v_0, v_1) = second_round(&x_0, h_0, &x_1, h_1);
        let x = output_computation(sigma, a_i, u, v_0, v_1);

        assert_eq!(x_1, x);
    }

    fn generate_test_inputs() -> (u8, Vec<u8>, Vec<u8>) {
        let sigma = rand::random::<bool>() as u8;
        let x_0 = FE::new_random().get_element().to_bytes().to_vec();
        let x_1 = FE::new_random().get_element().to_bytes().to_vec();
        (sigma, x_0, x_1)
    }

    fn generate_test_inputs_batch(n_parties: usize) -> (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let tmp_vec: Vec<_> = (0..n_parties).map(|_|{ generate_test_inputs() }).collect();
        let sigma_vec = tmp_vec.iter().map(|x|{x.0}).collect();
        let x_0_vec = tmp_vec.iter().map(|x|{x.1.clone()}).collect();
        let x_1_vec = tmp_vec.iter().map(|x|{x.2.clone()}).collect();
        (sigma_vec, x_0_vec, x_1_vec)
    }

    #[test]
    fn semi_honest_ot_batch_3() {
        let (sigma_vec, x_0_vec, x_1_vec) = generate_test_inputs_batch(3);
        let (a_i_vec, h_0_vec, h_1_vec) = first_round_batch(sigma_vec.clone());
        let (u_vec, v_0_vec, v_1_vec) = second_round_batch(x_0_vec.clone(), h_0_vec, x_1_vec.clone(), h_1_vec);
        let x_vec = output_computation_batch(sigma_vec.clone(), a_i_vec, u_vec, v_0_vec, v_1_vec);
        multizip((sigma_vec, x_vec, x_0_vec, x_1_vec)).map(|(sigma, x, x_0, x_1)|{
            if sigma == 0 { assert_eq!(x, x_0) }
            if sigma == 1 { assert_eq!(x, x_1) }
        }).for_each(drop);
    }
}
