use crate::adapter::Adapter;
use crate::model::Model;

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

pub struct FileAdapter {
    pub file_path: String,
}

type LoadPolicyFileHandler = fn(String, &mut Model);

impl FileAdapter {
    pub fn new(path: &str) -> Self {
        return FileAdapter {
            file_path: path.to_owned(),
        };
    }

    pub fn load_policy_file(&self, m: &mut Model, handler: LoadPolicyFileHandler) {
        let f = File::open(self.file_path.clone()).expect("read error");
        let f = BufReader::new(f);
        for line in f.lines() {
            handler(line.unwrap(), m);
        }
    }

    pub fn save_policy_file(&self, text: String) {
        let mut file = File::create(self.file_path.clone()).expect("read error");
        file.write_all(text.as_bytes()).unwrap();
    }
}

impl Adapter for FileAdapter {
    fn load_policy(&self, m: &mut Model) {
        self.load_policy_file(m, load_policy_line);
    }

    fn save_policy(&self, m: &mut Model) {
        if self.file_path == "" {
            panic!("文件地址不存在");
        }

        let mut tmp = String::new();
        let ast_map1 = m.model.get("p").unwrap();
        for (ptype, ast) in ast_map1 {
            for rule in &ast.policy {
                let s1 = format!("{}, {}\n", ptype, rule.join(","));
                tmp += s1.as_str();
            }
        }

        let ast_map2 = m.model.get("g").unwrap();
        for (ptype, ast) in ast_map2 {
            for rule in &ast.policy {
                let s1 = format!("{}, {}\n", ptype, rule.join(","));
                tmp += s1.as_str();
            }
        }
        return self.save_policy_file(tmp);
    }

    fn add_policy(&mut self, _sec: &str, _ptype: &str, _rule: Vec<&str>) -> bool {
        panic!("add_policy method not implemented yet");
    }
    fn remove_policy(&self, _sec: String, _ptype: String, _rule: Vec<String>) {
        panic!("remove_policy method not implemented yet");
    }
    fn remove_filtered_policy(
        &self,
        _sec: String,
        _ptype: String,
        _field_index: usize,
        _field_values: Option<Vec<String>>,
    ) {
        panic!("remove_filtered_policy method not implemented yet");
    }
}

fn load_policy_line(line: String, m: &mut Model) {
    if line == "" || line.chars().nth(0).unwrap() == '#' {
        return;
    }
    let mut tokens: Vec<String> = line.split(',').map(String::from).collect();
    for i in 0..tokens.len() {
        tokens[i] = tokens[i].trim().to_string();
    }
    let key = tokens[0].clone();
    let sec = key.chars().nth(0).unwrap().to_string();

    if let Some(t1) = m.model.get_mut(&sec) {
        if let Some(t2) = t1.get_mut(&key) {
            t2.policy.push(tokens[1..].to_vec());
        }
    }
}
