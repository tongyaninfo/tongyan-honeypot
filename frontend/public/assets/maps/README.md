# 世界底图来源

浏览器可读版本为 [attribution.txt](attribution.txt)，地图中的「地图来源」链接指向该文件。更新底图版本、来源、摘要、许可或用途时，须同步维护本文与该纯文本文件。

- 文件：[world-110m.json](world-110m.json)，仅用于运行总览的二维请求流向背景；业务来源与目标位置来自本系统接口，不来自地图示例数据。
- 固定版本：`world-atlas@2.0.2` 的 `countries-110m.json`。
- 上游：[topojson/world-atlas](https://github.com/topojson/world-atlas)，由 Natural Earth 数据生成 TopoJSON。
- 获取地址：[固定版本发行文件](https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json)。运行时从本系统同源资源读取，不连接该 CDN。
- 原始文件大小：107761 字节。
- SHA-256：`2516c915867c7baf18ddec727aec46c315541a07cfb3d79a6559b05d5e94eee8`。
- 软件许可：ISC，原文见 [LICENSE.world-atlas](LICENSE.world-atlas)，来自[同版本许可文件](https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/LICENSE)。
- 源地图数据：[Natural Earth 使用条款](https://www.naturalearthdata.com/about/terms-of-use/)说明其地图数据为公有领域。

本文件只用于低精度世界位置示意，不提供街道、导航或精确设备位置。IP 归属地本身是近似推断；未知位置不补造坐标。地图底图版本与 IP 位置数据版本分别记录，不能把底图发布时间当作定位数据版本。
