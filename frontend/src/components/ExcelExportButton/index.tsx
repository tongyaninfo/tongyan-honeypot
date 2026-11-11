import { DownloadOutlined } from '@ant-design/icons';
import { useIntl } from '@umijs/max';
import { Button, message } from 'antd';
import { useState } from 'react';
import { reportFrontendDiagnostic } from '@/services/frontendDiagnostics';
import { type ExcelCell, type ExcelSheet, exportExcel } from '@/utils/exportExcel';

type Props = {
  filename: string;
  sheetName: string;
  headers: string[];
  label?: string;
  disabled?: boolean;
} & (
  | { rows: () => ExcelCell[][]; additionalSheets?: () => Promise<ExcelSheet[]>; prepare?: never }
  | { prepare: () => Promise<{ rows: ExcelCell[][]; additionalSheets: ExcelSheet[] }>; rows?: never; additionalSheets?: never }
);

export default function ExcelExportButton({ filename, sheetName, headers, rows, additionalSheets, prepare, label, disabled }: Props) {
  const { formatMessage } = useIntl();
  const buttonLabel = label ?? formatMessage({ id: 'excel.export', defaultMessage: 'Export Excel' });
  const [loading, setLoading] = useState(false);
  const [notices, noticeHolder] = message.useMessage();

  const download = async () => {
    setLoading(true);
    try {
      const workbook = prepare ? await prepare() : { rows: rows(), additionalSheets: await additionalSheets?.() };
      await exportExcel(filename, sheetName, headers, workbook.rows, workbook.additionalSheets);
    } catch {
      reportFrontendDiagnostic('UI_EXPORT_FAILED');
      void notices.error(formatMessage({ id: 'excel.failed', defaultMessage: 'Excel export failed. Try again.' }));
    } finally {
      setLoading(false);
    }
  };

  return <>
    {noticeHolder}
    <Button aria-label={buttonLabel} icon={<DownloadOutlined aria-hidden />} disabled={disabled} loading={loading} onClick={download}>
      {buttonLabel}
    </Button>
  </>;
}
