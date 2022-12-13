using _Pustok.Models;

namespace _Pustok.ViewModels
{
    public class HomeViewModel
    {

        public List<Book> SpecialBooks { get; set; }
        public List<Book> NewBooks { get; set; }
        public List<Book> DiscountedBooks { get; set; }
        public List<Slider> Sliders { get; set; }
        public Dictionary<string,string> Settings { get; set; }
        public List<Feature> Features { get; set; }
    }
}
