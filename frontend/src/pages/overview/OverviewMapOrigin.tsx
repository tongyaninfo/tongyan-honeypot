import { Popover } from 'antd';
import { createStyles } from 'antd-style';
import { useRef, useState } from 'react';
import type { MapPoint } from './connectionMapGeometry';

const useStyles = createStyles(({ css, token }) => ({
  marker: css`
    cursor: help;
    &:focus-visible {
      outline: none;
      circle:first-of-type { stroke: ${token.colorPrimary}; stroke-width: 2; }
    }
  `,
  sources: css`
    min-width: min(204px, calc(100vw - 56px));
    max-width: min(350px, calc(100vw - 56px));
    max-height: min(180px, 40vh);
    overflow: auto;
    overscroll-behavior: contain;
    table { width: 100%; border-collapse: collapse; }
    caption { text-align: start; color: ${token.colorTextSecondary}; }
    th, td { padding: 3px 8px 3px 0; text-align: start; overflow-wrap: anywhere; }
    th { position: sticky; top: 0; background: ${token.colorBgElevated}; color: ${token.colorTextSecondary}; }
    td:first-child { font-variant-numeric: tabular-nums; }
  `,
}));

interface OverviewMapOriginProps {
  point: MapPoint;
  radius: number;
  markerScale: number;
  color: string;
  background: string;
  summary: string;
  sources: ReadonlyMap<string, string>;
  sourceIpCount?: number;
  getPopupContainer: () => HTMLElement;
}

export default function OverviewMapOrigin({
  point,
  radius,
  markerScale,
  color,
  background,
  summary,
  sources,
  sourceIpCount,
  getPopupContainer,
}: OverviewMapOriginProps) {
  const { styles } = useStyles();
  const [open, setOpen] = useState(false);
  const table = useRef<HTMLDivElement>(null);

  return (
    <Popover
      title={summary}
      open={open}
      onOpenChange={setOpen}
      trigger={['hover', 'focus', 'click']}
      mouseLeaveDelay={0.2}
      destroyOnHidden
      getPopupContainer={getPopupContainer}
      styles={{
        title: {
          maxWidth: 'min(350px, calc(100vw - 56px))',
          overflowWrap: 'anywhere',
        },
      }}
      content={
        <div ref={table} className={styles.sources}>
          <table aria-label="来源 IP 与国家">
            {sourceIpCount !== undefined && sourceIpCount > sources.size && (
              <caption>
                共 {sourceIpCount.toLocaleString('zh-CN')} 个来源 IP，显示最近{' '}
                {sources.size} 个
              </caption>
            )}
            <thead>
              <tr>
                <th scope="col">来源 IP</th>
                <th scope="col">国家</th>
              </tr>
            </thead>
            <tbody>
              {Array.from(sources, ([ip, country]) => (
                <tr key={ip}>
                  <td>{ip}</td>
                  <td>{country || '未知'}</td>
                </tr>
              ))}
              {sources.size === 0 && (
                <tr>
                  <td>—</td>
                  <td>未知</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      }
    >
      {/* biome-ignore lint/a11y/useSemanticElements: SVG 源点不能直接使用 HTML button，使用可聚焦组并实现键盘操作。 */}
      <g
        className={styles.marker}
        tabIndex={0}
        role="button"
        aria-label={summary}
        aria-expanded={open}
        onKeyDown={(event) => {
          if (event.key === 'Escape') setOpen(false);
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            setOpen(true);
          }
          const body = table.current;
          if (
            open &&
            body &&
            body.scrollHeight > body.clientHeight &&
            (event.key === 'ArrowDown' || event.key === 'ArrowUp')
          ) {
            event.preventDefault();
            body.scrollTop += event.key === 'ArrowDown' ? 32 : -32;
          }
        }}
      >
        <circle
          cx={point[0]}
          cy={point[1]}
          r={Math.max(9, radius + 2) * markerScale}
          fill="transparent"
          vectorEffect="non-scaling-stroke"
        />
        <circle
          cx={point[0]}
          cy={point[1]}
          r={radius * markerScale ** 1.2}
          fill={color}
          stroke={background}
          strokeWidth="1"
          vectorEffect="non-scaling-stroke"
        />
      </g>
    </Popover>
  );
}
