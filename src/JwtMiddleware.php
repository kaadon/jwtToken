<?php


namespace Kaadon\Jwt;


use Closure;
use think\Request;
use think\Response;
use think\facade\Config;

class JwtMiddleware
{
    /**
     * 处理请求
     *
     * @param Request $request
     * @param Closure $next
     * @return Response
     * @throws \Kaadon\Jwt\JwtException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $Currentoute = strtolower($request->pathinfo());
        $api_white_list = Config::get('jwt.white') ?? [];
        if (!in_array($Currentoute, $api_white_list)) {
            $tokenBearer = app('request')->header('Authorization');
            if (!$tokenBearer) {
                throw new JwtException('token is must.');
            }
            $request->JwtData = Jwt::verify($tokenBearer);
        }
        return $next($request);
    }
}
