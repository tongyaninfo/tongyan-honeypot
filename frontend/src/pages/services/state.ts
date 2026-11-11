export type ServiceRuntimeState = 'Running' | 'Starting' | 'Stopped' | 'Failed';

export function isServiceRunning(currentState?: string, runtimeStates: string[] = []) {
  return currentState === 'Running'
    || currentState === 'Starting'
    || runtimeStates.some((state) => state === 'Running' || state === 'Starting');
}

export function resolveServiceState(currentState?: string, runtimeStates: string[] = []): ServiceRuntimeState {
  if (currentState === 'Running' || runtimeStates.includes('Running')) {
    return 'Running';
  }
  if (currentState === 'Starting' || runtimeStates.includes('Starting')) {
    return 'Starting';
  }
  if (currentState === 'Failed' || runtimeStates.includes('Failed')) {
    return 'Failed';
  }
  return 'Stopped';
}
