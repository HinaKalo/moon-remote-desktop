# MoonRemote

由 `dotnet new lumen-app` 生成的 Avalonia 12 + [Lumen.UI](https://github.com/HinaKalo/CSharpGUIFramework) 桌面应用。

## 运行

```bash
dotnet run --project src/MoonRemote
```

## 结构

```
MoonRemote.slnx
Directory.Build.props        公共编译选项；LumenUiVersion（包版本）或 LumenUiProject（源码路径）
publish.ps1 / publish.sh     一键打包并输出体积
src/MoonRemote/
  App.axaml                  挂载 LumenTheme
  ViewModels/                CommunityToolkit.Mvvm（MainWindowViewModel 里配置侧边导航）
  Views/                     MainWindow（AppShell）、HomePage、SettingsPage
  Properties/PublishProfiles 三种发布配置
```

升级组件库：改 `Directory.Build.props` 里的 `LumenUiVersion`（可用版本见 https://www.nuget.org/packages/Lumen.UI ）。

新增页面：在 `Views/` 加一个 UserControl（`x:DataType` 指向它的 ViewModel），再在 `MainWindowViewModel.NavItems` 里加一行 `new("标题", IconKind.Xxx, () => new XxxPage { DataContext = new XxxViewModel() })`。

## 打包

```powershell
./publish.ps1                 # 默认：裁剪后的自包含单文件
./publish.ps1 -Mode aot       # Native AOT
./publish.ps1 -Mode all -Zip  # 三种都打，并各生成 zip，最后打印体积对比
./publish.ps1 -Runtime win-arm64
```

| 模式 | 发布配置 | 产物 | 适用 |
| --- | --- | --- | --- |
| `fd` | FrameworkDependent | 单个 exe，目标机需装 .NET 10 运行时 | 体积最小，内部工具 |
| `trimmed` | SelfContained | 单个压缩 exe，已裁剪，免安装 | 默认分发方式 |
| `aot` | NativeAot | 原生 exe + Skia/HarfBuzz 原生库，免安装 | 启动最快；需要 C++ 工具链，只能打本机系统 |

产物在 `artifacts/publish/<模式>/`。也可以直接用 `dotnet publish src/MoonRemote -p:PublishProfile=SelfContained`。

### 进一步压缩体积（可选）

在对应 `.pubxml` 里追加：

- `<InvariantGlobalization>true</InvariantGlobalization>`：不使用区域性格式（日期 / 数字按不变区域显示）。
- `<UseSystemResourceKeys>true</UseSystemResourceKeys>`：去掉异常消息文本，报错只剩资源键。
- `<SatelliteResourceLanguages>en</SatelliteResourceLanguages>`：只保留英文卫星资源。

裁剪 / AOT 依赖编译绑定和无反射代码。项目已开启 `IsAotCompatible`，平时构建就会报出不兼容的写法；新增代码保持 0 警告即可放心裁剪。
