using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using bdapi_auth.Models;
using Microsoft.EntityFrameworkCore;
using bdapi_auth.Services;

namespace bdapi_auth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            string PostgresConnection;
            if (Environment.GetEnvironmentVariable("ENV") == "prod")
            {
                string template = "Server=buildarium.postgres.database.azure.com;Database=auth;Port=5432;User Id={0};Password={1};Ssl Mode=Require;";
                PostgresConnection = string.Format(template, Environment.GetEnvironmentVariable("POSTGRESUSER"), Environment.GetEnvironmentVariable("POSTGRESPASS"));
            }
            else if (Environment.GetEnvironmentVariable("ENV") == "test")
            {
                string template = "User ID={0};Password={1};Server=postgres;Port=5432;Database=postgres;Integrated Security=true;Pooling=true;";
                PostgresConnection = string.Format(template, Environment.GetEnvironmentVariable("POSTGRESUSER"), Environment.GetEnvironmentVariable("POSTGRESPASS"));
            }
            else
            {
                PostgresConnection = Configuration.GetConnectionString("DefaultConnection");
            }
            Console.WriteLine(PostgresConnection);
            services.AddDbContext<UserService>(options =>
               options.UseNpgsql(PostgresConnection)
            );
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                //app.UseHsts();
            }

            //app.UseHttpsRedirection();
            app.UseMvc();
        }
    }
}
