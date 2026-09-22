package cn.safeagent.biz.common.config;

import cn.safeagent.biz.common.security.AuthInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web 配置：注册统一鉴权拦截器。
 * 放行公开端点（/api/auth/login、/swagger/**、/v3/api-docs/**、健康检查）。
 * 其余端点无论匿名与否均解析身份，controller 按需判定（admin/任意登录）。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AuthInterceptor authInterceptor;

    public WebConfig(AuthInterceptor authInterceptor) {
        this.authInterceptor = authInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                        "/api/auth/login",
                        "/api/auth/sso/config",
                        "/actuator/health",
                        "/actuator/health/**",
                        "/health",
                        "/swagger-ui/**",
                        "/swagger-ui.html",
                        "/v3/api-docs/**"
                );
    }
}