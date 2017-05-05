// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Linq;
using System.Reflection;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using NetEscapades.AspNetCore.SecurityHeaders;
using QuickstartIdentityServer.Data;
using QuickstartIdentityServer.Models;

namespace QuickstartIdentityServer {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            var connectionString = @"server=localhost;database=IdentityServer4;User Id=sa;Password=@Clave123_456";
            var migrationsAssembly = typeof (Startup).GetTypeInfo().Assembly.GetName().Name;

            services.AddDbContext<ApplicationDbContext>(builder =>
                builder.UseSqlServer(connectionString));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            // configure identity server with in-memory stores, keys, clients and scopes
            var identityServerBuilder = services.AddIdentityServer()
                .AddTemporarySigningCredential();
            identityServerBuilder.AddConfigurationStore(builder =>
                builder.UseSqlServer(connectionString, options =>
                    options.MigrationsAssembly(migrationsAssembly)));
            identityServerBuilder.AddOperationalStore(builder =>
                builder.UseSqlServer(connectionString, options =>
                    options.MigrationsAssembly(migrationsAssembly)));
            identityServerBuilder.AddAspNetIdentity<ApplicationUser>();

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory) {
            loggerFactory.AddConsole(LogLevel.Debug);
            InitializeDatabase(app);
            app.UseDeveloperExceptionPage();

            app.UseIdentity();
            app.UseIdentityServer();

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }

        private void InitializeDatabase(IApplicationBuilder app) {
            using(var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope()) {
                serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();
                if (!context.Clients.Any()) {
                    foreach(var client in Config.GetClients()) {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.IdentityResources.Any()) {
                    foreach(var resource in Config.GetIdentityResources()) {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any()) {
                    foreach(var resource in Config.GetApiResources()) {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
            }
        }

    }
}