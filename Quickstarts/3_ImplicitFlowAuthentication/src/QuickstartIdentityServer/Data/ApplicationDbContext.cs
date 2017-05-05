using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using QuickstartIdentityServer.Models;

namespace QuickstartIdentityServer.Data {
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser> {
        string connectionString = @"server=localhost;database=IdentityServer4;User Id=sa;Password=@Clave123_456";
        string devServer = @"server=devserver;database=MasivIII;User Id=testuser;Password=123456";
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) {
            optionsBuilder.UseSqlServer(connectionString);
        }
    }
}