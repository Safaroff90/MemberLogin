using System.ComponentModel.DataAnnotations;

namespace _Pustok.Models
{
    public class BookImage
    {
        public int Id { get; set; }
        public int BookId { get; set; }
        [MaxLength(100)]
        public string Name { get; set; }
        public bool? Status { get; set; }

        public Book Book { get; set; }
    }

}
