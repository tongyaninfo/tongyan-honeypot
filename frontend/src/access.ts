/**
 * @see https://umijs.org/docs/max/access#access
 * */
export default function access(
  initialState: { currentUser?: API.CurrentUser } | undefined,
) {
  const { currentUser } = initialState ?? {};
  return {
    // 模板的 access 字段并非身份 API 合同，不能用它代替服务端角色。
    canAdmin: currentUser?.roles?.some((role) => ['administrator', 'admin'].includes(role.toLowerCase())) === true,
  };
}
