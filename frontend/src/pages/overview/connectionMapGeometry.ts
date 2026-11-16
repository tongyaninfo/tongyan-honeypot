import { geoNaturalEarth1, geoPath } from 'd3';
import { feature } from 'topojson-client';
import type { GeometryCollection, Topology } from 'topojson-specification';

export type MapPoint = [number, number];
export const mapWidth = 1000;
export const mapHeight = 456;

const maxZoom = 4;

export interface MapViewport {
  scale: number;
  x: number;
  y: number;
}

export const initialMapViewport: MapViewport = { scale: 1, x: 0, y: 0 };

export function viewSize(view: MapViewport): MapPoint {
  return [mapWidth / view.scale, mapHeight / view.scale];
}

export function panMap(view: MapViewport, x: number, y: number): MapViewport {
  const [width, height] = viewSize(view);
  // 全图也可以微调位置。向地图外留出的边距随缩放收窄。
  const marginX = Math.max(0, width * 1.12 - mapWidth);
  const marginY = Math.max(0, height * 1.12 - mapHeight);
  return {
    scale: view.scale,
    x: Math.min(Math.max(x, -marginX), mapWidth - width + marginX),
    y: Math.min(Math.max(y, -marginY), mapHeight - height + marginY),
  };
}

export function zoomMap(
  view: MapViewport,
  factor: number,
  anchor: MapPoint,
): MapViewport {
  const scale = Math.max(1, Math.min(maxZoom, view.scale * factor));
  if (scale === view.scale) return view;
  const [oldWidth, oldHeight] = viewSize(view);
  const next = { ...view, scale };
  const [width, height] = viewSize(next);
  // 放大时保持指针下的地理位置，直到碰到地图边界。
  return panMap(
    next,
    view.x + (oldWidth - width) * anchor[0],
    view.y + (oldHeight - height) * anchor[1],
  );
}

export function viewportAnchor(
  rect: DOMRect,
  clientX: number,
  clientY: number,
): MapPoint {
  // SVG 等比居中。全屏时两侧或上下可能留空，按实际投影区域计算指针位置。
  const ratio = Math.min(rect.width / mapWidth, rect.height / mapHeight);
  if (!(ratio > 0)) return [0.5, 0.5];
  const width = mapWidth * ratio;
  const height = mapHeight * ratio;
  return [
    Math.min(
      1,
      Math.max(0, (clientX - rect.left - (rect.width - width) / 2) / width),
    ),
    Math.min(
      1,
      Math.max(0, (clientY - rect.top - (rect.height - height) / 2) / height),
    ),
  ];
}

const projection = geoNaturalEarth1().fitExtent(
  [
    [16, 10],
    [mapWidth - 16, mapHeight - 10],
  ],
  { type: 'Sphere' },
);

export async function loadWorldPath(signal: AbortSignal) {
  const response = await fetch('/assets/maps/world-110m.json', { signal });
  if (!response.ok) throw new Error('Map asset unavailable');
  const topology = (await response.json()) as Topology<{
    countries: GeometryCollection;
  }>;
  if (
    topology.type !== 'Topology' ||
    topology.objects?.countries?.type !== 'GeometryCollection'
  ) {
    throw new Error('Invalid map asset');
  }
  const path = geoPath(projection)(
    feature(topology, topology.objects.countries),
  );
  if (!path) throw new Error('Empty map asset');
  return path;
}

export function coordinates(location: {
  longitude?: number | null;
  latitude?: number | null;
}): MapPoint | null {
  const { longitude, latitude } = location;
  return typeof longitude === 'number' &&
    Number.isFinite(longitude) &&
    Math.abs(longitude) <= 180 &&
    typeof latitude === 'number' &&
    Number.isFinite(latitude) &&
    Math.abs(latitude) <= 90
    ? [longitude, latitude]
    : null;
}

export function mapPosition(point: MapPoint) {
  return projection(point);
}

export function flightPath(from: MapPoint, to: MapPoint) {
  const height = Math.min(
    112,
    Math.max(16, Math.hypot(from[0] - to[0], from[1] - to[1]) * 0.22),
  );
  const controlX = (from[0] + to[0]) / 2;
  const controlY = Math.max(3, (from[1] + to[1]) / 2 - height);
  return `M${from[0]},${from[1]} Q${controlX},${controlY} ${to[0]},${to[1]}`;
}

const adapters = [
  'ssh',
  'rdp',
  'telnet',
  'mysql',
  'mssql',
  'mongodb',
  'postgresql',
  'redis',
  'oracle',
  'db2',
  'memcached',
  'hbase',
  'influxdb',
  'elasticsearch',
  'smb',
  'nfs',
];

export function serviceColor(adapterKey: string, dark: boolean) {
  const key = adapterKey.toLowerCase();
  const index = adapters.indexOf(key);
  // 使用固定顺序取色，图例与跨窗口出现的同一服务保持一致。
  const hue = index < 0 ? 210 : Math.round(index * 137.508) % 360;
  return `hsl(${hue} ${index < 0 ? 15 : 77}% ${dark ? 66 : 39}%)`;
}
