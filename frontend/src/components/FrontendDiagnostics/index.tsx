import { useEffect } from 'react';
import { installFrontendDiagnostics } from '@/services/frontendDiagnostics';

export default function FrontendDiagnostics() {
  useEffect(() => installFrontendDiagnostics(), []);
  return null;
}
