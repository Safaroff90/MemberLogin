using System.ComponentModel.DataAnnotations;

namespace _Pustok.Areas.Manage.ViewModels
{
	public class AdminLoginViewModel
	{
        [MaxLength(25)]
        public string Username { get; set; }
        [MaxLength(20)]
        public string Password { get; set; }
        public bool IsPersist { get; set; }
    }
}
