using System.ComponentModel.DataAnnotations;

namespace _Pustok.ViewModels
{
    public class MemberRegisterViewModel
    {
        [MaxLength(25)]
        public string Username { get; set; }
        [MaxLength(25)]
        public string Fullname { get; set; }
        [MaxLength(100)]
        public string Email { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [MaxLength(20)]
        [Compare("Password",ErrorMessage="Password don't match")]
        public string ConfirmPassword { get; set; }

    }
}
