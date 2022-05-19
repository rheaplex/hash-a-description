// Copyright 2022 Rhea Myers <rhea@myers.studio>.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use regex::Regex;
use sha256::digest;
use std::sync::Arc;
use std::thread;

// We generate lots of very similar prefixes to have the best chance of
// producing a hash that matches when we prefix a statement with them.

const HASH: [&str; 6] = [
    "hash",
    "cryptographic hash",
    "sha256",
    "SHA256",
    "sha256 hash",
    "SHA256 hash",
];
const HASH_ACTION: [&str; 5] = [
    "hashing",
    "cryptographic hashing",
    "cryptographically hashing",
    "sha256 hashing",
    "SHA256 hashing",
];
const SUBJECT: [&str; 4] = ["this", "this text", "this sentence", "this statement"];
const RELATION: [&str; 3] = ["contains", "has", "includes"];
const RESULT: [&str; 4] = ["results in", "produces", "creates", "outputs"];
const HASH_RESULT: [&str; 5] = [
    "a string",
    "a digest",
    "a hexadecimal string",
    "a message digest",
    "a hexadecimal message digest",
];

//const NUMBERS: [&str; 16] = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "A", "B", "C", "D", "E", "F"];
//const NUMBERS_PLURAL: [&str; 16] = ["zeros", "ones", "twos", "threes", "fours", "fives", "sixes", "sevens", "eights", "nines", "As", "Bs", "Cs", "Ds", "Es", "Fs"];

fn initial_cap(text: &str) -> String {
    let result = String::from(&text[..1]).to_uppercase();
    return result + &text[1..];
}

fn gen_prefixes() -> Vec<String> {
    let mut prefixes = Vec::new();
    // e.g. "the sha256 hash of this text includes"
    for hash in HASH {
        for subject in SUBJECT {
            for relation in RELATION {
                let prefix = format!("the {} of {} {}", hash, subject, relation);
                prefixes.push(initial_cap(&prefix));
                prefixes.push(prefix);
            }
        }
    }
    // e.g. "SHA256 hashing this statement outputs a digest that has"
    for hash_action in HASH_ACTION {
        for subject in SUBJECT {
            for result in RESULT {
                for hash_result in HASH_RESULT {
                    for relation in RELATION {
                        let prefix = format!(
                            "{} {} {} {} that {}",
                            hash_action, subject, result, hash_result, relation
                        );
                        // e.g. if the string *doesn't* start with SHA256
                        if prefix.chars().next().unwrap().is_lowercase() {
                            prefixes.push(initial_cap(&prefix));
                        }
                        prefixes.push(prefix);
                    }
                }
            }
        }
    }
    return prefixes;
}

// If there's a match, print it

fn maybe_print_description_match(description: &str, matcher: &Regex) {
    let hash = digest(description.clone());
    //println!("{} {}", description, hash);
    if matcher.is_match(&hash) {
        println!("{}: {}", description, hash);
    }
}

// Look for the described feature, using the provided matcher, fuzzing with prefixes

fn maybe_find_feature(feature: &str, matcher: &Regex, prefixes: &Vec<String>) {
    for prefix in prefixes {
        let description = format!("{} {}", prefix, feature);
        maybe_print_description_match(&description, matcher);
    }
}

// Look for the described feature, using the provided matcher,
// matching AT LEAST count times, fuzzing with prefixes

fn maybe_find_feature_count(feature: &str, matcher: &Regex, count: usize, prefixes: &Vec<String>) {
    for prefix in prefixes {
        let description = format!("{} {}", prefix, feature);
        let hash = digest(description.clone());
        //println!("{} {}", description, hash);
        if matcher.captures_iter(&hash).count() == count {
            println!("{}: {}", description, hash);
        }
    }
}

// Look for 0..F, matching > 1 times, fuzzing with prefixes

fn maybe_find_more_than_one(prefixes: &Arc<Vec<String>>) {
    for digit in 0..15 {
        let p = prefixes.clone();
        thread::spawn(move || {
            let matcher = Regex::new(format!(r"{:x}{{2,}}", digit).as_str()).unwrap();
            for qualifier in ["more than one", "multiple"] {
                maybe_find_feature(&format!("{} {:x}", qualifier, digit), &matcher, &p);
                // Use uppercase hex digits as well.
                if digit > 9 {
                    maybe_find_feature(&format!("{} {:X}", qualifier, digit), &matcher, &p);
                }
            }
        });
    }
}

// Look for 0..F, matching 5..15 times, fuzzing with prefixes

fn maybe_find_n(prefixes: &Arc<Vec<String>>) {
    for digit in 0..15 {
        for count in 5..15 {
            let p = prefixes.clone();
            thread::spawn(move || {
                let matcher = Regex::new(format!(r"{:x}", digit).as_str()).unwrap();
                maybe_find_feature_count(&format!("{} {:x}s", count, digit), &matcher, count, &p);
                // Use uppercase hex digits as well.
                if digit > 9 {
                    maybe_find_feature_count(
                        &format!("{} {:X}s", count, digit),
                        &matcher,
                        count,
                        &p,
                    );
                }
            });
        }
    }
}

// Look for 0..F, matching 5.15 times SUCCESSIVELY, fuzzing with prefixes

fn maybe_find_n_successive(prefixes: &Arc<Vec<String>>) {
    for n in 0..15 {
        for m in 5..15 {
            let p = prefixes.clone();
            thread::spawn(move || {
                let matcher = Regex::new(format!(r"{:x}{{{},}}", n, m).as_str()).unwrap();
                maybe_find_feature(&format!("{} successive {:x}s", m, n), &matcher, &p);
                maybe_find_feature(&format!("{} successive {:X}s", m, n), &matcher, &p);
                maybe_find_feature(&format!("{} {:x}s successively", m, n), &matcher, &p);
                maybe_find_feature(&format!("{} {:X}s successively", m, n), &matcher, &p);
            });
        }
    }
}

// Look for two different runs of 0..F, matching 5.15 times SUCCESSIVELY, fuzzing with prefixes
// FIXME: describe and/or find exact matches

fn maybe_find_n_and_m_successive(prefixes: &Arc<Vec<String>>) {
    for digit1 in 0..15 {
        for digit2 in 0..15 {
            if digit1 != digit2 {
                for count1 in 3..15 {
                    for count2 in 3..15 {
                        let p = prefixes.clone();
                        thread::spawn(move || {
                            let matcher = Regex::new(
                                format!(r"{:x}{{{}}}.*{:x}{{{}}}", digit1, count1, digit2, count2)
                                    .as_str(),
                            )
                            .unwrap();
                            maybe_find_feature(
                                &format!("{} {:x}s and {} {:x}s", count1, digit1, count2, digit2),
                                &matcher,
                                &p,
                            );
                        });
                    }
                }
            }
        }
    }
}

fn main() {
    let prefixes = Arc::new(gen_prefixes());
    maybe_find_more_than_one(&prefixes);
    maybe_find_n(&prefixes);
    maybe_find_n_successive(&prefixes);
    maybe_find_n_and_m_successive(&prefixes);
}
