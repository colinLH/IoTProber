import geopandas as gpd
from shapely.geometry import Point
import matplotlib.pyplot as plt
import pandas as pd
from pyecharts.charts import *
from pyecharts import options as opts


def plot_wordmap(locations: list, protocol: str, scan_day: str):
    geometry = [Point(lon, lat) for lat, lon in locations]
    gdf = gpd.GeoDataFrame(locations, geometry=geometry, columns=["Latitude", "Longitude"])
    # 加载世界地图
    # world = gpd.read_file(get_path("nybb"))
    world = gpd.read_file("https://naciscdn.org/naturalearth/110m/cultural/ne_110m_admin_0_countries.zip")
    fig, ax = plt.subplots(figsize=(16, 12))
    # 绘制世界地图
    world.plot(ax=ax, color='lightgray')
    # 在地图上标注位置
    index = 1
    for _, row in gdf.iterrows():
        if index % 1000 == 0:
            print("Scattering {}".format(index))
        index += 1
        ax.scatter(row['Longitude'], row['Latitude'], color='red', s=5, zorder=5)

    ax.set_title(f"{protocol} Backend Distributions-Day {scan_day}", fontsize=15)
    plt.savefig("distribution.jpg", dpi=300, bbox_inches='tight')
    # plt.show()


def plot_wordmap2(location_file: str, save_html: str):
    geo = Geo(init_opts=opts.InitOpts(theme='dark', bg_color='#000000', width='1000px', height='800px'))
    df = pd.read_csv(location_file)

    # 将数据分为强中弱三类
    weak, strong, normal = [], [], []
    for idx, row in df.iterrows():
        if row.num < 10:
            weak.append((idx, row.num))
            geo.add_coordinate(idx, row.lon, row.lat)
        elif 10 <= row.num < 30:
            normal.append((idx, row.num))
            geo.add_coordinate(idx, row.lon, row.lat)
        elif row.num >= 30:
            strong.append((idx, row.num))
            geo.add_coordinate(idx, row.lon, row.lat)

    geo.add_schema(maptype="world", is_roam=False, zoom=1.2,
                   itemstyle_opts=opts.ItemStyleOpts(color="#000000", border_color="#1E90FF"),
                   emphasis_label_opts=opts.LabelOpts(is_show=False),
                   emphasis_itemstyle_opts=opts.ItemStyleOpts(color="#323c48"))

    geo.add("Weak",
            weak,
            type_='scatter',
            #         is_selected=True,
            symbol_size=1,
            is_large=True,
            itemstyle_opts=opts.ItemStyleOpts(color="#1E90FF"))

    geo.add("Medium",
            normal,
            type_='scatter',
            #         is_selected=True,
            symbol_size=1,
            is_large=True,
            itemstyle_opts=opts.ItemStyleOpts(color="#00FFFF"))

    geo.add("Strong",
            strong,
            type_='scatter',
            #         is_selected=True,
            symbol_size=1,
            is_large=True,
            itemstyle_opts=opts.ItemStyleOpts(color="#E1FFFF"))

    geo.set_series_opts(label_opts=opts.LabelOpts(is_show=False))

    geo.set_global_opts(
        title_opts=opts.TitleOpts(title="Censys 253,252 MQTT Backend Distribution", pos_top='top', pos_left='center'),
        tooltip_opts=opts.TooltipOpts(is_show=False),
        legend_opts=opts.LegendOpts(is_show=True, pos_left='left', orient='vertical'))

    geo.js_dependencies.add("echarts-gl")

    geo.options['series'][0]['type'] = 'scatterGL'
    geo.options['series'][1]['type'] = 'scatterGL'
    geo.options['series'][2]['type'] = 'scatterGL'

    geo.render(save_html)
