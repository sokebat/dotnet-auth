
using dotnet_auth.Domain.Model;
using Microsoft.EntityFrameworkCore;

namespace dotnet_auth.data
{
    public class StudentConfiguration : IEntityTypeConfiguration<Student>
    {
        public void Configure(Microsoft.EntityFrameworkCore.Metadata.Builders.EntityTypeBuilder<Student> builder)
        {
          builder.HasOne<ApplicationUser>()
                 .WithMany()
                 .HasForeignKey(s => s.ApplicationUserId)
                 .OnDelete(DeleteBehavior.Restrict);
        }
    }

}
