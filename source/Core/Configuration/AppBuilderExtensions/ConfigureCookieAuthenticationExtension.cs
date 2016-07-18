/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Configuration.Hosting;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Services;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataHandler;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Owin
{
    internal static class UseCookieAuthenticationExtension
    {
        public interface IIdSrvCookieManager : Microsoft.Owin.Infrastructure.ICookieManager { RequestCookieCollection GetCookiesNames(Microsoft.Owin.IOwinContext context); }

        public class SystemWebIdSrvCookieManager : IIdSrvCookieManager
        {
            public string GetRequestCookie(IOwinContext context, string key)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }

                var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);
                var cookie = webContext.Request.Cookies[key];
                return cookie == null ? null : cookie.Value;
            }

            public void AppendResponseCookie(IOwinContext context, string key, string value, Microsoft.Owin.CookieOptions options)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }
                if (options == null)
                {
                    throw new ArgumentNullException("options");
                }

                var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);

                bool domainHasValue = !string.IsNullOrEmpty(options.Domain);
                bool pathHasValue = !string.IsNullOrEmpty(options.Path);
                bool expiresHasValue = options.Expires.HasValue;

                var cookie = new HttpCookie(key, value);
                if (domainHasValue)
                {
                    cookie.Domain = options.Domain;
                }
                if (pathHasValue)
                {
                    cookie.Path = options.Path;
                }
                if (expiresHasValue)
                {
                    cookie.Expires = options.Expires.Value;
                }
                if (options.Secure)
                {
                    cookie.Secure = true;
                }
                if (options.HttpOnly)
                {
                    cookie.HttpOnly = true;
                }

                webContext.Response.AppendCookie(cookie);
            }

            public void DeleteCookie(IOwinContext context, string key, Microsoft.Owin.CookieOptions options)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }
                if (options == null)
                {
                    throw new ArgumentNullException("options");
                }

                AppendResponseCookie(
                    context,
                    key,
                    string.Empty,
                    new Microsoft.Owin.CookieOptions
                    {
                        Path = options.Path,
                        Domain = options.Domain,
                        Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    });
            }

            public RequestCookieCollection GetCookiesNames(IOwinContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }

                var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);

                var coockies = webContext.Response.Cookies;
                var dicc = new Dictionary<string, string>();
                foreach (var cookieName in coockies.AllKeys)
                {
                    dicc.Add(cookieName, coockies[cookieName].Value);
                }

                return new RequestCookieCollection(dicc);
            }
        }

        public static IAppBuilder ConfigureCookieAuthentication(this IAppBuilder app, IdentityServer3.Core.Configuration.CookieOptions options, IDataProtector dataProtector)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (dataProtector == null) throw new ArgumentNullException("dataProtector");

            if (options.Prefix.IsPresent())
            {
                options.Prefix += ".";
            }

            var cookieManager = new SystemWebIdSrvCookieManager();
            var primary = new CookieAuthenticationOptions
            {
                CookieManager = cookieManager,
                AuthenticationType = Constants.PrimaryAuthenticationType,
                CookieName = options.Prefix + Constants.PrimaryAuthenticationType,
                ExpireTimeSpan = options.ExpireTimeSpan,
                SlidingExpiration = options.SlidingExpiration,
                CookieSecure = GetCookieSecure(options.SecureMode),
                TicketDataFormat = new TicketDataFormat(new DataProtectorAdapter(dataProtector, options.Prefix + Constants.PrimaryAuthenticationType)),
                SessionStore = GetSessionStore(options.SessionStoreProvider),
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = async cookieCtx =>
                    {
                        var validator = cookieCtx.OwinContext.Environment.ResolveDependency<IAuthenticationSessionValidator>();
                        var isValid = await validator.IsAuthenticationSessionValidAsync(new ClaimsPrincipal(cookieCtx.Identity));
                        if (isValid == false)
                        {
                            cookieCtx.RejectIdentity();
                        }
                    }
                }
            };
            app.UseCookieAuthentication(primary);

            var external = new CookieAuthenticationOptions
            {
                CookieManager = cookieManager,
                AuthenticationType = Constants.ExternalAuthenticationType,
                CookieName = options.Prefix + Constants.ExternalAuthenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                ExpireTimeSpan = Constants.ExternalCookieTimeSpan,
                SlidingExpiration = false,
                CookieSecure = GetCookieSecure(options.SecureMode),
                TicketDataFormat = new TicketDataFormat(new DataProtectorAdapter(dataProtector, options.Prefix + Constants.ExternalAuthenticationType))
            };
            app.UseCookieAuthentication(external);

            var partial = new CookieAuthenticationOptions
            {
                CookieManager = cookieManager,
                AuthenticationType = Constants.PartialSignInAuthenticationType,
                CookieName = options.Prefix + Constants.PartialSignInAuthenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                ExpireTimeSpan = options.ExpireTimeSpan,
                SlidingExpiration = options.SlidingExpiration,
                CookieSecure = GetCookieSecure(options.SecureMode),
                TicketDataFormat = new TicketDataFormat(new DataProtectorAdapter(dataProtector, options.Prefix + Constants.PartialSignInAuthenticationType))
            };
            app.UseCookieAuthentication(partial);

            Action<string> setCookiePath = path =>
            {
                if (!String.IsNullOrWhiteSpace(path))
                {
                    primary.CookiePath = external.CookiePath = path;
                    partial.CookiePath = path;
                }
            };
            
            if (String.IsNullOrWhiteSpace(options.Path))
            {
                app.Use(async (ctx, next) =>
                {
                    // we only want this to run once, so assign to null once called 
                    // (and yes, it's possible that many callers hit this at same time, 
                    // but the set is idempotent)
                    if (setCookiePath != null)
                    {
                        setCookiePath(ctx.Request.PathBase.Value);
                        setCookiePath = null;
                    }
                    await next();
                });
            }
            else
            {
                setCookiePath(options.Path);
            }

            return app;
        }

        private static CookieSecureOption GetCookieSecure(CookieSecureMode cookieSecureMode)
        {
            switch (cookieSecureMode)
            {
                case CookieSecureMode.Always:
                    return CookieSecureOption.Always;
                case CookieSecureMode.SameAsRequest:
                    return CookieSecureOption.SameAsRequest;
                default:
                    throw new InvalidOperationException("Invalid CookieSecureMode");
            }
        }

        private static IAuthenticationSessionStore GetSessionStore(IAuthenticationSessionStoreProvider provider)
        {
            return provider != null ? new AuthenticationSessionStoreWrapper(provider) : null;
        }
    }
}