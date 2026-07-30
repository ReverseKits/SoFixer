# SoFixer
用于修复从内存中 dump 下来的So文件。

#### dump_memory_so.cpp
在android手机上执行用于dump so数据

用原始 SO 的 `PT_LOAD.p_memsz` 计算完整内存范围，因此会包含与 SO
相邻的 `[anon:.bss]` 映射：

```shell
dump_memory_so <pid> <so-name-or-path> <original-so> <output-file>
```

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
