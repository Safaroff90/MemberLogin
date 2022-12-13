using System.ComponentModel.DataAnnotations;

namespace _Pustok.Attributes.ValidationAttributes
{
    public class AllowedFileTypes : ValidationAttribute
    {
        string[] _fileTypes;
        public AllowedFileTypes(params string[] fileTypes)
        {
            _fileTypes = fileTypes;
        }

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            var file = value as IFormFile;
            if (file != null)
            {
                if (!_fileTypes.Contains(file.ContentType))
                    return new ValidationResult("File Content type must be one of these types: " + String.Join(", ", _fileTypes));
            }

            return ValidationResult.Success;
        }

    }
}
