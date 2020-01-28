use super::gf8::GF8;

pub fn two_p_mul<'a>(p1_result: &'a mut Vec<GF8>, p2: &[GF8]) -> &'a Vec<GF8> {
    let orig_p1 = p1_result.clone();
    for p1_i in p1_result.iter_mut() {
        *p1_i = GF8::new(0);
    }

    for (skip_items, xx) in p2.iter().enumerate() {
        // print!("skipping {}: ", skip_items);
        for (out_it, in_it) in p1_result.iter_mut().skip(skip_items).zip(orig_p1.iter()) {
            *out_it = (out_it as &GF8) + &(xx * in_it);
            // print!("{} ", xx * in_it);
        }
        // println!("");
        p1_result.push(GF8::new(0));
    }

    // shrink to empty Vec if multiplied by zero polynomial
    if !p2.is_empty() {
        p1_result.pop();
    } else {
        p1_result.clear();
    }

    p1_result
}

pub fn two_p_sum<'a>(p1: &'a mut Vec<GF8>, p2: &[GF8]) -> &'a Vec<GF8> {
    let length = std::cmp::max(p1.len(), p2.len());
    let p1_orig = p1.clone();

    p1.clear();
    while p1.len() + p1_orig.len() < length {
        p1.push(GF8::new(0));
    }
    p1.extend(p1_orig.iter());

    for (it1, it2) in p1.iter_mut().skip(length - p2.len()).zip(p2.iter()) {
        *it1 = (it1 as &GF8) + it2;
    }
    p1
}

#[cfg(test)]
mod test {
    use super::*;

    impl std::fmt::Display for GF8 {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    #[test]
    fn test_summation() {
        let mut p1 = vec![GF8::new(3), GF8::new(2), GF8::new(8)];
        let mut q1 = p1.clone();

        let p2 = vec![GF8::new(1), GF8::new(9), GF8::new(3)];
        let p3 = vec![GF8::new(1), GF8::new(9)];
        let mut p4: Vec<GF8> = vec! [];
        let mut q4: Vec<GF8> = vec! [];

        assert_eq!(*two_p_sum(&mut p1, &p2), [GF8::new(2), GF8::new(11), GF8::new(11)]);
        assert_eq!(*two_p_sum(&mut q1, &p3), [GF8::new(3), GF8::new(3), GF8::new(1)]);
        assert_eq!(*two_p_sum(&mut p4, &p2), p2);
        assert_eq!(*two_p_sum(&mut q4, & vec! []), []);
    }

    #[test]
    fn test_multiplication() {
        let mut p1 = vec![GF8::new(3), GF8::new(2), GF8::new(8)];
        let mut q1 = p1.clone();

        let mut r1 = p1.clone();
        let r2 = vec! [GF8::new(1)];
        let r3 = r1.clone();

        let p2 = vec![GF8::new(1), GF8::new(9), GF8::new(3)];
        let p0: Vec<GF8> = vec! [];

        let product = vec![GF8::new(0x3), GF8::new(0x19), GF8::new(0x1f), GF8::new(0x4e), GF8::new(0x18)];
        assert_eq!(*two_p_mul(&mut p1, &p2), product);
        assert_eq!(*two_p_mul(&mut q1, &p0), p0);
        assert_eq!(*two_p_mul(&mut r1, &r2), r3);
    }
}