import { FullscreenExitOutlined, FullscreenOutlined } from '@ant-design/icons';
import { HubConnectionState } from '@microsoft/signalr';
import { Button, Card, Select, Switch, Typography } from 'antd';
import { createStyles } from 'antd-style';
import {
  type PointerEvent,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type {
  ConnectionMapEvent,
  ConnectionMapSnapshot,
  ConnectionMapWindowSeconds,
} from '@/services/honeypot/api';
import {
  coordinates,
  flightPath,
  initialMapViewport,
  loadWorldPath,
  type MapPoint,
  type MapViewport,
  mapPosition,
  panMap,
  serviceColor,
  viewSize,
  viewportAnchor,
  zoomMap,
} from './connectionMapGeometry';
import OverviewMapOrigin from './OverviewMapOrigin';
import { arrivalDuration, flightDuration } from './useOverviewConnectionMap';

const useStyles = createStyles(({ css, token }) => ({
  shell: css`
    position: relative;
  `,
  fullscreen: css`
    width: 100%;
    height: 100%;
    background: ${token.colorBgContainer};
  `,
  fullscreenFallback: css`
    position: fixed;
    inset: 0;
    z-index: ${token.zIndexPopupBase + 10};
    overscroll-behavior: contain;
  `,
  fullscreenCard: css`
    display: flex;
    flex-direction: column;
    height: 100%;
  `,
  fullscreenBody: css`
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  `,
  map: css`
    position: relative;
    display: grid;
    align-items: center;
    min-height: 164px;
    overflow: hidden;
    border: 1px solid ${token.colorBorderSecondary};
    border-radius: ${token.borderRadiusLG}px;
    background: radial-gradient(ellipse at top, ${token.colorFillSecondary}, ${token.colorBgContainer} 85%);
    svg { display: block; width: 100%; max-height: 420px; touch-action: none; user-select: none; }
  `,
  fullscreenMap: css`
    flex: 1;
    min-height: 0;
    grid-template-rows: minmax(0, 1fr);
    svg { height: 100%; max-height: none; }
  `,
  mapUnavailable: css`
    place-self: center;
    padding: ${token.paddingLG}px;
    color: ${token.colorTextSecondary};
  `,
  flightControls: css`
    display: inline-flex;
    align-items: center;
    gap: ${token.marginXXS}px;
    white-space: nowrap;
  `,
  headerControls: css`
    display: flex;
    align-items: center;
    gap: ${token.marginXS}px;
    flex-wrap: wrap;
    justify-content: flex-end;
    padding-block: ${token.paddingXXS}px;
  `,
  footer: css`
    display: grid;
    gap: ${token.marginXS}px;
    margin-top: ${token.marginSM}px;
    font-size: ${token.fontSizeSM}px;
  `,
  details: css`
    display: flex;
    flex-wrap: wrap;
    gap: ${token.marginXXS}px ${token.marginMD}px;
    align-items: center;
    color: ${token.colorTextSecondary};
  `,
  windowControl: css`
    display: inline-flex;
    align-items: center;
    gap: ${token.marginXXS}px;
    white-space: nowrap;
  `,
  swatch: css`
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-inline-end: 4px;
  `,
  flight: css`
    pointer-events: none;
    @media (prefers-reduced-motion: reduce) { display: none; }
  `,
}));

interface MapViewProps {
  dark: boolean;
  windowSeconds: ConnectionMapWindowSeconds;
  selectWindow: (value: ConnectionMapWindowSeconds) => void;
  snapshot?: ConnectionMapSnapshot;
  unavailable: boolean;
  flightEvents: ConnectionMapEvent[];
  connectionState: HubConnectionState;
  paused: boolean;
  reducedMotion: boolean;
  pause: (value: boolean) => void;
}

const windowOptions = [
  { value: 60, label: '60 秒' },
  { value: 600, label: '10 分钟' },
  { value: 7200, label: '2 小时' },
  { value: 86400, label: '24 小时' },
] satisfies { value: ConnectionMapWindowSeconds; label: string }[];

interface MapDrag {
  pointerId: number;
  clientX: number;
  clientY: number;
  scale: number;
  viewport: MapViewport;
}

interface OriginMarker {
  id: string;
  point: MapPoint;
  adapterKey: string;
  locationLabel: string;
  count: number;
  sources: Map<string, string>;
  sourceIpCount?: number;
}

function collectOrigins(snapshot?: ConnectionMapSnapshot): OriginMarker[] {
  if (snapshot?.origins) {
    return snapshot.origins.flatMap((origin) => {
      const location = coordinates(origin);
      const point = location ? mapPosition(location) : null;
      if (!point || origin.connectionCount < 1) return [];
      return [
        {
          id: origin.id,
          point,
          adapterKey: origin.adapterKey,
          locationLabel: origin.locationLabel,
          count: origin.connectionCount,
          sources: new Map(
            origin.sources.map(({ ip, country }) => [ip, country]),
          ),
          sourceIpCount: origin.sourceIpCount,
        },
      ];
    });
  }

  // 兼容旧版 API，当时来源点由逐连接快照合并。
  const result = new Map<string, OriginMarker & { occurredAtUtc: string }>();
  for (const event of snapshot?.events ?? []) {
    const location = coordinates(event);
    if (!location) continue;
    const key = `${location[0].toFixed(2)},${location[1].toFixed(2)}`;
    let origin = result.get(key);
    if (!origin) {
      const point = mapPosition(location);
      if (!point) continue;
      origin = {
        id: key,
        point,
        adapterKey: event.adapterKey,
        locationLabel: event.locationLabel,
        occurredAtUtc: event.occurredAtUtc,
        count: 0,
        sources: new Map(),
      };
      result.set(key, origin);
    }
    origin.count++;
    if (event.occurredAtUtc > origin.occurredAtUtc) {
      origin.occurredAtUtc = event.occurredAtUtc;
      origin.adapterKey = event.adapterKey;
      origin.locationLabel = event.locationLabel;
    }
    // 同一个 IP 多次连接只展示一次；已有国家信息时不被空值覆盖。
    const ip = event.sourceIp?.trim();
    if (ip && !origin.sources.get(ip))
      origin.sources.set(ip, event.country?.trim() ?? '');
  }
  return [...result.values()];
}

const connectionLabels: Record<HubConnectionState, string | undefined> = {
  [HubConnectionState.Connected]: undefined,
  [HubConnectionState.Connecting]: '正在连接',
  [HubConnectionState.Reconnecting]: '实时通道重连中',
  [HubConnectionState.Disconnected]: '实时通道已断开',
  [HubConnectionState.Disconnecting]: '实时通道已断开',
};

const numberFormat = new Intl.NumberFormat('zh-CN');
const shanghaiTime = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  dateStyle: 'short',
  timeStyle: 'medium',
  hourCycle: 'h23',
});
const serviceLabel = (key: string) => key.trim().toUpperCase() || '未知服务';

function targetLabel(snapshot?: ConnectionMapSnapshot) {
  switch (snapshot?.target.status) {
    case 'ready': {
      const label = snapshot.target.label || '蜜罐部署位置';
      const updatedAt = Date.parse(snapshot.target.updatedAtUtc ?? '');
      const time = Number.isFinite(updatedAt)
        ? ` · ${shanghaiTime.format(updatedAt)}`
        : '';
      return snapshot.target.stale ? `${label}（上次已知${time}）` : label;
    }
    case 'pending':
      return '正在解析蜜罐部署位置';
    case 'disabled':
      return 'IP 归属地未开启';
    case 'unavailable':
      return '蜜罐部署位置不可用';
    default:
      return undefined;
  }
}

function MapFlight({
  path,
  target,
  markerScale,
  color,
  background,
  className,
}: {
  path: string;
  target: MapPoint;
  markerScale: number;
  color: string;
  background: string;
  className: string;
}) {
  const group = useRef<SVGGElement>(null);
  useLayoutEffect(() => {
    // 动态插入的 SMIL 按当前 SVG 时间启动；父级重新渲染时不会重新起飞。
    group.current
      ?.querySelectorAll<SVGAnimationElement>('[data-offset]')
      .forEach((animation) => {
        animation.beginElementAt?.(Number(animation.dataset.offset));
      });
  }, []);

  const duration = `${flightDuration}ms`;
  const arrival = `${arrivalDuration}ms`;
  const arrivalOffset = flightDuration / 1000;
  return (
    <g ref={group} className={className}>
      <g>
        <animate
          attributeName="opacity"
          from="1"
          to="0"
          dur="180ms"
          begin="indefinite"
          data-offset={arrivalOffset}
          fill="freeze"
        />
        <path
          d={path}
          fill="none"
          stroke={color}
          opacity="0.23"
          strokeWidth="1"
          vectorEffect="non-scaling-stroke"
        />
        <path
          d={path}
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
          pathLength="100"
          strokeDasharray="10 90"
          strokeDashoffset="100"
          vectorEffect="non-scaling-stroke"
        >
          <animate
            attributeName="stroke-dashoffset"
            from="100"
            to="10"
            dur={duration}
            begin="indefinite"
            data-offset="0"
            fill="freeze"
          />
        </path>
        <circle
          r={4 * markerScale ** 1.2}
          fill={color}
          stroke={background}
          strokeWidth="0.8"
          vectorEffect="non-scaling-stroke"
        >
          <animateMotion
            path={path}
            dur={duration}
            begin="indefinite"
            data-offset="0"
            fill="freeze"
          />
        </circle>
      </g>
      <circle
        transform={`translate(${target[0]} ${target[1]}) scale(${markerScale})`}
        r="5"
        opacity="0"
        fill="none"
        stroke={color}
        strokeWidth="2"
        vectorEffect="non-scaling-stroke"
      >
        <animate
          attributeName="r"
          from="5"
          to="24"
          dur={arrival}
          begin="indefinite"
          data-offset={arrivalOffset}
          fill="freeze"
        />
        <animate
          attributeName="opacity"
          from="0.9"
          to="0"
          dur={arrival}
          begin="indefinite"
          data-offset={arrivalOffset}
          fill="freeze"
        />
      </circle>
    </g>
  );
}

export default function OverviewConnectionMap({
  dark,
  windowSeconds,
  selectWindow,
  snapshot,
  unavailable,
  flightEvents,
  connectionState,
  paused,
  reducedMotion,
  pause,
}: MapViewProps) {
  const { styles, theme, cx } = useStyles();
  const [worldPath, setWorldPath] = useState<string>();
  const [assetFailed, setAssetFailed] = useState(false);
  const [viewport, setViewport] = useState(initialMapViewport);
  const [panning, setPanning] = useState(false);
  const [nativeFullscreen, setNativeFullscreen] = useState(false);
  const [fullscreenFallback, setFullscreenFallback] = useState(false);
  const shell = useRef<HTMLElement>(null);
  const map = useRef<SVGSVGElement>(null);
  const drag = useRef<MapDrag>(null);
  const fullscreen = nativeFullscreen || fullscreenFallback;
  const live = !paused && !reducedMotion;
  const getPopupContainer = () => shell.current ?? document.body;

  useEffect(() => {
    const controller = new AbortController();
    void loadWorldPath(controller.signal)
      .then((path) => {
        if (!controller.signal.aborted) setWorldPath(path);
      })
      .catch(() => {
        if (!controller.signal.aborted) setAssetFailed(true);
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const svg = map.current;
    if (!worldPath || !svg) return;
    const handleWheel = (event: WheelEvent) => {
      const unit = event.deltaMode;
      if (!Number.isFinite(event.deltaY) || event.deltaY === 0) return;
      const rect = svg.getBoundingClientRect();
      const pixels =
        event.deltaY * (unit === 1 ? 16 : unit === 2 ? rect.height : 1);
      event.preventDefault();
      if (drag.current) return;
      const anchor = viewportAnchor(rect, event.clientX, event.clientY);
      // 触摸板捏合在支持的浏览器中发送带 Ctrl 的滚轮事件，增大细小手势的响应。
      const factor = Math.exp(-pixels * (event.ctrlKey ? 0.012 : 0.002));
      setViewport((view) => zoomMap(view, factor, anchor));
    };
    // 显式关闭 passive，避免缩放地图时同时滚动页面或缩放浏览器。
    svg.addEventListener('wheel', handleWheel, { passive: false });
    return () => svg.removeEventListener('wheel', handleWheel);
  }, [worldPath]);

  useEffect(() => {
    const syncFullscreen = () =>
      setNativeFullscreen(document.fullscreenElement === shell.current);
    document.addEventListener('fullscreenchange', syncFullscreen);
    return () =>
      document.removeEventListener('fullscreenchange', syncFullscreen);
  }, []);

  useEffect(() => {
    if (!fullscreenFallback) return;
    const exitOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented)
        setFullscreenFallback(false);
    };
    document.addEventListener('keydown', exitOnEscape);
    return () => document.removeEventListener('keydown', exitOnEscape);
  }, [fullscreenFallback]);

  async function toggleFullscreen() {
    const container = shell.current;
    if (!container) return;
    if (fullscreenFallback) {
      setFullscreenFallback(false);
      return;
    }
    if (document.fullscreenElement === container) {
      await document.exitFullscreen();
      return;
    }
    if (container.requestFullscreen) {
      try {
        await container.requestFullscreen();
        return;
      } catch {
        // 没有浏览器全屏权限的窗口仍可使用页面内全屏。
      }
    }
    setFullscreenFallback(true);
  }

  const origins = useMemo(() => collectOrigins(snapshot), [snapshot]);
  const targetCoordinates =
    snapshot?.target.status === 'ready' ? coordinates(snapshot.target) : null;
  const target = targetCoordinates ? mapPosition(targetCoordinates) : null;
  const flights = useMemo(
    () =>
      flightEvents.flatMap((event) => {
        const location = coordinates(event);
        const from = location ? mapPosition(location) : null;
        return from && target
          ? [{ event, path: flightPath(from, target) }]
          : [];
      }),
    [flightEvents, target],
  );
  const legend = useMemo(
    () =>
      [
        ...new Set([
          ...(snapshot?.adapterKeys ??
            (snapshot?.events ?? [])
              .filter((event) => coordinates(event))
              .map((event) => event.adapterKey)),
          ...flightEvents.map((event) => event.adapterKey),
        ]),
      ].sort(),
    [snapshot, flightEvents],
  );
  const coverage = snapshot?.coverage;
  const awaitingLookup = coverage?.deferred ?? 0;
  const locating = Math.max(0, (coverage?.pending ?? 0) - awaitingLookup);
  const targetDescription = targetLabel(snapshot);
  const [viewWidth, viewHeight] = viewSize(viewport);
  // SVG 视野放大时反向调整标记。来源和飞线点稍微缩小，命中范围和落点涟漪保持原屏幕尺寸。
  const markerScale = 1 / viewport.scale;
  const windowLabel =
    windowOptions.find(({ value }) => value === windowSeconds)?.label ??
    '10 分钟';
  const containsPoint = ([x, y]: MapPoint) =>
    x >= viewport.x &&
    x <= viewport.x + viewWidth &&
    y >= viewport.y &&
    y <= viewport.y + viewHeight;
  const labelToLeft =
    target && target[0] > viewport.x + viewWidth - 94 * markerScale;

  function startPanning(event: PointerEvent<SVGSVGElement>) {
    if (
      !event.isPrimary ||
      event.button !== 0 ||
      (event.target instanceof Element &&
        event.target.closest('[role="button"]'))
    )
      return;
    const rect = event.currentTarget.getBoundingClientRect();
    // SVG 默认等比居中，缩放后依旧用同一套投影坐标移动视野。
    const scale = Math.min(rect.width / viewWidth, rect.height / viewHeight);
    if (!Number.isFinite(scale) || scale <= 0) return;
    drag.current = {
      pointerId: event.pointerId,
      clientX: event.clientX,
      clientY: event.clientY,
      scale,
      viewport,
    };
    event.currentTarget.setPointerCapture?.(event.pointerId);
    setPanning(true);
  }

  function moveViewport(event: PointerEvent<SVGSVGElement>) {
    const start = drag.current;
    if (start?.pointerId !== event.pointerId) return;
    const x = start.viewport.x - (event.clientX - start.clientX) / start.scale;
    const y = start.viewport.y - (event.clientY - start.clientY) / start.scale;
    setViewport(panMap(start.viewport, x, y));
  }

  function stopPanning(event: PointerEvent<SVGSVGElement>) {
    if (drag.current?.pointerId !== event.pointerId) return;
    drag.current = null;
    setPanning(false);
  }

  return (
    <section
      ref={shell}
      className={cx(
        styles.shell,
        fullscreen && styles.fullscreen,
        fullscreenFallback && styles.fullscreenFallback,
      )}
      aria-label="全球连接地图"
    >
      <Card
        size="small"
        title="全球连接地图"
        className={fullscreen ? styles.fullscreenCard : undefined}
        classNames={fullscreen ? { body: styles.fullscreenBody } : undefined}
        extra={
          <div className={styles.headerControls}>
            <div className={styles.flightControls}>
              <Typography.Text type={live ? 'secondary' : undefined}>
                暂停飞线
              </Typography.Text>
              <Switch
                size="small"
                aria-label="实时飞线"
                checked={live}
                onChange={(enabled) => pause(!enabled)}
                disabled={reducedMotion}
              />
              <Typography.Text type={live ? undefined : 'secondary'}>
                实时
              </Typography.Text>
            </div>
            <Button
              size="small"
              aria-label="复位地图"
              disabled={
                !worldPath ||
                (viewport.scale === 1 && viewport.x === 0 && viewport.y === 0)
              }
              onClick={() => setViewport(initialMapViewport)}
            >
              复位
            </Button>
            <Button
              size="small"
              aria-label={fullscreen ? '退出全屏' : '全屏地图'}
              title={fullscreen ? '退出全屏' : '全屏地图'}
              icon={
                fullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />
              }
              onClick={() => void toggleFullscreen()}
            />
          </div>
        }
      >
        <div className={cx(styles.map, fullscreen && styles.fullscreenMap)}>
          {worldPath ? (
            <svg
              ref={map}
              viewBox={`${viewport.x} ${viewport.y} ${viewWidth} ${viewHeight}`}
              aria-label={`最近 ${windowLabel}连接来源分布`}
              style={{ cursor: panning ? 'grabbing' : 'grab' }}
              onPointerDown={startPanning}
              onPointerMove={moveViewport}
              onPointerUp={stopPanning}
              onPointerCancel={stopPanning}
              onLostPointerCapture={stopPanning}
            >
              <path
                d={worldPath}
                fill={theme.colorFillSecondary}
                stroke={theme.colorBorder}
                strokeWidth="0.6"
              />
              {origins
                .filter(({ point }) => containsPoint(point))
                .map(
                  ({
                    id,
                    point,
                    adapterKey,
                    locationLabel,
                    count,
                    sources,
                    sourceIpCount,
                  }) => (
                    <OverviewMapOrigin
                      key={id}
                      point={point}
                      radius={Math.min(8, 3.7 + Math.log2(count))}
                      markerScale={markerScale}
                      color={serviceColor(adapterKey, dark)}
                      background={theme.colorBgContainer}
                      summary={`${locationLabel || '来源位置'} · ${sourceIpCount === undefined ? '' : '最近 '}${serviceLabel(adapterKey)} · ${numberFormat.format(count)} 次连接`}
                      sources={sources}
                      sourceIpCount={sourceIpCount}
                      getPopupContainer={getPopupContainer}
                    />
                  ),
                )}
              {target && containsPoint(target) && (
                <g
                  pointerEvents="none"
                  transform={`translate(${target[0]} ${target[1]}) scale(${markerScale})`}
                >
                  <title>{targetDescription}</title>
                  <circle
                    r="11"
                    fill="none"
                    stroke={theme.colorText}
                    strokeWidth="1.2"
                    vectorEffect="non-scaling-stroke"
                  />
                  <circle r="4.5" fill={theme.colorText} />
                  <text
                    x={labelToLeft ? -16 : 16}
                    y={-8}
                    textAnchor={labelToLeft ? 'end' : 'start'}
                    fontSize="15"
                    fill={theme.colorText}
                    stroke={theme.colorBgContainer}
                    strokeWidth="3"
                    paintOrder="stroke"
                  >
                    蜜罐
                  </text>
                </g>
              )}
              {!paused &&
                !reducedMotion &&
                target &&
                flights.map(({ event, path }) => (
                  <MapFlight
                    key={event.id}
                    path={path}
                    target={target}
                    markerScale={markerScale}
                    color={serviceColor(event.adapterKey, dark)}
                    background={theme.colorBgContainer}
                    className={styles.flight}
                  />
                ))}
            </svg>
          ) : (
            <span className={styles.mapUnavailable}>
              {assetFailed ? '世界底图暂不可用' : '正在加载世界底图…'}
            </span>
          )}
        </div>
        <div className={styles.footer}>
          <div className={styles.details}>
            <div className={styles.windowControl}>
              <span>最近</span>
              <Select<ConnectionMapWindowSeconds>
                aria-label="地图时间范围"
                size="small"
                value={windowSeconds}
                options={windowOptions}
                onChange={selectWindow}
                getPopupContainer={getPopupContainer}
                virtual={false}
                style={{ minWidth: 84 }}
              />
            </div>
            {unavailable && <span role="status">连接地图数据暂不可用</span>}
            {connectionLabels[connectionState] && (
              <span role="status">{connectionLabels[connectionState]}</span>
            )}
            {!snapshot && !unavailable && <span>正在获取连接来源…</span>}
            {snapshot && !snapshot.locationEnabled && (
              <span>IP 归属地未开启</span>
            )}
            {coverage && (
              <span>
                已定位 {numberFormat.format(coverage.mapped)} / 观测{' '}
                {numberFormat.format(coverage.observed)}
              </span>
            )}
            {coverage && coverage.private > 0 && (
              <span>
                内网及保留地址 {numberFormat.format(coverage.private)}
              </span>
            )}
            {locating > 0 && (
              <span title="已进入归属地解析队列">
                定位中 {numberFormat.format(locating)}
              </span>
            )}
            {awaitingLookup > 0 && (
              <span title="尚未进入归属地解析队列，后续刷新会分批补查">
                等待定位 {numberFormat.format(awaitingLookup)}
              </span>
            )}
            {coverage && coverage.unknown > 0 && (
              <span>无位置 {numberFormat.format(coverage.unknown)}</span>
            )}
            {snapshot?.origins === undefined &&
              coverage &&
              coverage.omitted > 0 && (
                <span>
                  超出展示上限 {numberFormat.format(coverage.omitted)}
                </span>
              )}
            {snapshot?.locationEnabled && targetLabel(snapshot) && (
              <span>部署点 {targetLabel(snapshot)}</span>
            )}
          </div>
          {legend.length > 0 && (
            <section className={styles.details} aria-label="服务配色">
              {legend.map((service) => (
                <span key={service}>
                  <span
                    className={styles.swatch}
                    style={{ backgroundColor: serviceColor(service, dark) }}
                  />
                  {serviceLabel(service)}
                </span>
              ))}
            </section>
          )}
          <a
            href="/assets/maps/attribution.txt"
            target="_blank"
            rel="noreferrer"
          >
            底图来源与许可
          </a>
        </div>
      </Card>
    </section>
  );
}
