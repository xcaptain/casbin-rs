# casbin-rs

用rust实现的一个casbin，目前正在大力开发中

## 如何测试

```shell
cargo test
```

如果使用vscode并且安装了lldb扩展的话，可以直接按下`F5`运行测试用例，并且添加断点调试代码

## TODO

- [x] 基本的匹配功能
- [ ] 从conf文件中创建model
- [ ] rbac匹配
- [ ] 错误处理
- [ ] Enforcer中role manager, effector, adapter做成trait
- [ ] 一个postgresql的adapter
