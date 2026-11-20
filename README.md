# SoFixer
用于修复从内存中 dump 下来的So文件。

#### dump_memory_so.cpp
在android手机上执行用于dump so数据

在 Linux 或 macOS 上使用 Android NDK 交叉编译：

```shell
ANDROID_NDK_HOME=/path/to/android-ndk ./build_dump_memory_so.sh
```

默认编译 `arm64-v8a`，最低系统版本为 Android API 24，产物位于
`build/android/arm64-v8a/api-24/dump_memory_so`。可传入 ABI 和 API
级别，例如 `./build_dump_memory_so.sh armeabi-v7a 24`。脚本也支持
`x86_64` 和 `x86`，并接受 `ANDROID_NDK_ROOT` 作为 NDK 路径。

用原始 SO 的 `PT_LOAD.p_memsz` 计算完整内存范围，因此会包含与 SO
相邻的 `[anon:.bss]` 映射：

```shell
dump_memory_so <pid> <module-base> <original-so> <output-file>
```

参数说明：

- `pid`：目标进程 PID。
- `module-base`：模块实际加载基址，以十六进制传入，支持带或不带 `0x`
  前缀。该地址应使用 Frida 的 `Process.getModuleByName("libjiagu_sdk_SDKProtected.so").base`，不再根据
  `/proc/<pid>/maps` 中同路径首次出现的映射推断。
- `original-so`：用于读取 ELF Header 和 `PT_LOAD` 布局的原始 SO。
- `output-file`：内存 dump 输出路径。

例如：

```shell
dump_memory_so 25961 0x78a88b8000 \
  ./libjiagu_sdk_SDKProtected.so \
  ./libjiagu_sdk_dump.so
```

可以通过 Frida 获取 `module-base`：

```javascript
const module = Process.getModuleByName("libjiagu_sdk_SDKProtected.so");
console.log("module base: " + module.base);
```

`dump_memory_so` 仍会读取 `/proc/<pid>/maps`，但只用于确定模块地址范围内
实际可读的映射、保留映射空洞和包含相邻的匿名 BSS，不再用于选择模块
加载基址。

成功后还会生成 `<output-file>.maps`，其中记录完整 ELF 范围内各映射的
RVA、权限和运行时 ELF 基址，供 SoFixer 重建 section 和修复重定位使用。

## Build
```shell
mkdir build
cd build
# 参数 -DSO_64=ON 用于修复64位so文件，不添加则为修复32位so文件
cmake -DSO_64=ON ..
make
```

## 使用方法
* 從so中dump內存， ida腳本
```$cpp
import idaapi
start_address = 0x0000007DB078B000
end_address = 0x0000007DB08DE000
data_length = end_address - start_address
fp = open('E:\path.so', 'wb')

cur = 0
towrite = 0x100000
while cur < data_length:
    if data_length - cur < 0x100000:
        towrite = data_length - cur
    data = idaapi.dbg_read_memory(start_address + cur, towrite)
    fp.write(data)
    cur = cur + towrite

fp.close()
```
* 执行修复
```$cpp
sofixer -s source_dump.so -o fix.so -d
-s 待修復的so路徑
-o 修復後的so路徑
-d 輸出debug信息
```

SoFixer 会自动读取与 dump 文件同名的 `.maps` 元数据文件，例如
`source_dump.so.maps`，从中获取运行时基址和各内存区间的权限。

## 原理
原理参考下面的文章  
TK so修复参考[http://bbs.pediy.com/thread-191649.htm]
* 修复shdr
* 修复phdr
* 修复重定位

## 已知问题
在解析重定位表的时候有几个地方写错了，暂时懒得改，估计够用了，等出现新的修复so的
理论的时候再一并更新吧
