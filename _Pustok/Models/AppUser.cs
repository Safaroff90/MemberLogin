using Microsoft.AspNetCore.Identity;

namespace _Pustok.Models
{
    public class AppUser:IdentityUser
    {
        public string Fullname { get; set; }
    }
}
