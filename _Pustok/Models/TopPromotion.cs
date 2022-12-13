using System.ComponentModel.DataAnnotations;

namespace _Pustok.Models
{
    public class TopPromotion
    {
        public int Id { get; set; }
        [MaxLength(100)]
        public string Image { get; set; }
        public string RedirectUrl { get; set; }
    }
}
