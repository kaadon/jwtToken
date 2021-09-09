<?php


namespace Kaadon\Jwt;


use Closure;
use think\Request;
use think\Response;
use think\facade\Config;
use Kaadon\Jwt\Jwt;

class JwtMiddleware
{
    /**
     * 处理请求
     *
     * @param Request $request
     * @param Closure $next
     * @return Response
     */
    public function handle($request, Closure $next)
    {
        $admin_menu_url = admin_menu_url();
        $api_white_list = Config::get('admin.api_white_list');

        if (!in_array($admin_menu_url, $api_white_list)) {
            $admin_token = admin_token();

            if (empty($admin_token)) {
                error('缺少参数:AdminToken');
            }

            $admin_user_id = admin_user_id();

            if (empty($admin_user_id)) {
                error('缺少参数:AdminUserId');
            }

            Jwt::verify($admin_token, $admin_user_id);
        }

        return $next($request);
    }
}
