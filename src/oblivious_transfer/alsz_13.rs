use curv::elliptic::curves::ed25519::{GE, FE};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};

// TODO: make it work on vectors, currently only single-shot
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
    let a_sigma = FE::new_random();
    let (h_0, h_1) = if sigma == 0 {
        let h_0 = g*a_sigma;
        let h_1 = g*FE::new_random();  // TODO: sample from G without knowing exponent
        (h_0, h_1)
    } else {
        let h_0 = g*FE::new_random();
        let h_1 = g*a_sigma;
        (h_0, h_1)
    };
    (a_sigma, h_0, h_1)
}

pub fn second_round(x_0: GE, h_0: GE, x_1: GE, h_1: GE) -> (GE, GE, GE) {
    let g = GE::generator();
    let r = FE::new_random();
    let u = g*r;
    let v_0 = h_0*r + x_0;
    let v_1 = h_1*r + x_1;
    (u, v_0, v_1)
}

pub fn output_computation(sigma: u8, a_sigma: FE, u: GE, v_0: GE, v_1: GE) -> GE {
    assert!(sigma == 0 || sigma == 1);
    let v = if sigma == 0 {v_0} else {v_1};
    let x = v.sub_point(&(u*a_sigma).get_element());
    x
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semi_honest_ot() {
        let sigma = 0;
        let x_0 = GE::generator()*FE::new_random();
        let x_1 = GE::generator()*FE::new_random();

        let (a_sigma, h_0, h_1) = first_round(sigma);
        let (u, v_0, v_1) = second_round(x_0, h_0, x_1, h_1);
        let x = output_computation(sigma, a_sigma, u, v_0, v_1);

        assert_eq!(x_0, x);

        let sigma = 1;
        let x_0 = GE::generator()*FE::new_random();
        let x_1 = GE::generator()*FE::new_random();

        let (a_sigma, h_0, h_1) = first_round(sigma);
        let (u, v_0, v_1)  = second_round(x_0, h_0, x_1, h_1);
        let x = output_computation(sigma, a_sigma, u, v_0, v_1);

        assert_eq!(x_1, x);
    }
}