pub trait RoleManager {
    fn clear(&mut self);
    fn add_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>);
    fn delete_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>);
    fn has_link(&self, name1: &str, name2: &str, domain: Vec<&str>) -> bool;
    fn get_roles(&self, name: &str, domain: Vec<&str>) -> Vec<&str>;
    fn get_users(&self, name: &str, domain: Vec<&str>) -> Vec<&str>;
    fn print_roles(&self);
}

use std::collections::HashMap;

type MatchingFunc = fn(&str, &str) -> bool;

#[derive(Clone)]
pub struct DefaultRoleManager {
    pub all_roles: HashMap<String, Role>,
    pub max_hierarchy_level: usize,
    pub has_pattern: bool,
    pub matching_func: Option<MatchingFunc>,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        return DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level,
            has_pattern: false,
            matching_func: None,
        };
    }

    fn create_role(&mut self, name: &str) -> Role {
        // TODO: 加上 has_pattern 判断
        let role = self
            .all_roles
            .entry(name.to_owned())
            .or_insert(Role::new(name.to_owned()))
            .clone();
        return role;
    }

    fn has_role(&self, name: &str, hierarchy_level: Option<usize>) -> bool {
        // TODO: 添加完整实现
        return true;
    }
}

impl RoleManager for DefaultRoleManager {
    fn add_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>) {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if domain.len() == 1 {
            name1 = format!("{}::{}", domain[0], name1);
            name2 = format!("{}::{}", domain[0], name2);
        } else if domain.len() > 1 {
            panic!("error domain length");
        }
        let mut role1 = self.create_role(name1.as_str());
        let role2 = self.create_role(name2.as_str());
        role1.add_role(role2);
    }

    fn delete_link(&mut self, name1: &str, name2: &str, domain: Vec<&str>) {
        let mut name1 = name1.to_owned();
        let mut name2 = name2.to_owned();
        if domain.len() == 1 {
            name1 = format!("{}::{}", domain[0], name1);
            name2 = format!("{}::{}", domain[0], name2);
        } else if domain.len() > 1 {
            panic!("error domain length");
        }
        if !self.has_role(&name1, None) || !self.has_role(&name2, None) {
            panic!("name12 error");
        }
        let mut role1 = self.create_role(&name1);
        let role2 = self.create_role(&name2);
        role1.delete_role(role2);
    }

    fn has_link(&self, name1: &str, name2: &str, domain: Vec<&str>) -> bool {
        return true;
    }

    fn get_roles(&self, name: &str, domain: Vec<&str>) -> Vec<&str> {
        return vec![];
    }

    fn get_users(&self, name: &str, domain: Vec<&str>) -> Vec<&str> {
        return vec![];
    }

    fn print_roles(&self) {
        println!("print_roles tbd");
    }

    fn clear(&mut self) {
        // TODO: 清空当前对象
        self.all_roles = HashMap::new();
    }
}

#[derive(Clone)]
pub struct Role {
    pub name: String,
    pub roles: Vec<Box<Role>>,
}

impl Role {
    pub fn new(name: String) -> Self {
        return Role {
            name,
            roles: vec![],
        };
    }

    pub fn add_role(&mut self, other_role: Role) {
        for old_role in self.roles.iter() {
            if old_role.name == other_role.name {
                return;
            }
        }
        self.roles.push(Box::new(other_role));
    }

    fn delete_role(&mut self, other_role: Role) {
        if let Some(pos) = self
            .roles
            .iter()
            .cloned()
            .position(|x| x.name == other_role.name)
        {
            self.roles.remove(pos);
        }
    }
}
