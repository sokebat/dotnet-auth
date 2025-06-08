namespace dotnet_auth.Domain.Model
{
    public class Student
    {
        public int Id { get; set; }      
        public string Name { get; set; }
        public int Age { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string ApplicationUserId { get; set; } 
    }
}
