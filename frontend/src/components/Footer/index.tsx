import { createStyles } from 'antd-style';
import React from 'react';

const useStyles = createStyles(({ token, css }) => ({
  footer: css`
    display: flex;
    justify-content: center;
    padding: 12px 24px;
  `,
  link: css`
    display: inline-flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    color: ${token.colorTextSecondary};
    font-size: ${token.fontSizeSM}px;
    line-height: ${token.lineHeight};
    text-decoration: none;
    transition: color ${token.motionDurationMid};

    &:hover {
      color: ${token.colorLink};
      text-decoration: underline;
    }
  `,
  logo: css`
    display: block;
    flex: none;
    border-radius: ${token.borderRadiusSM}px;
    /* 为透明 Logo 的深蓝色字样提供浅色底，保证深色模式下可读。 */
    background: #fff;
  `,
}));

const Footer: React.FC = () => {
  const { styles } = useStyles();

  return (
    <footer className={styles.footer}>
      <a
        className={styles.link}
        href="https://www.tongyaninfo.com/"
        target="_blank"
        rel="noopener noreferrer"
      >
        <img
          className={styles.logo}
          src="/assets/brand/tyinfo-logo-horizontal_mini.png"
          alt=""
          width={108}
          height={36}
        />
        <span>TongYanInfo Site</span>
      </a>
    </footer>
  );
};

export default Footer;
