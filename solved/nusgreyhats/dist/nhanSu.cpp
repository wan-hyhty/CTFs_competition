// viet mot chuong trinh quan ly nhan su,
/*
    1. Them 1 nhan vien bat ki
    2. Xoa 1 nhan vien bat ki
    3. Tim nhan vien co luong lon nhat
*/

#include <iostream>
#include <string>
using namespace std;

class Person
{
private:
    string name;
    string address;
    int age;

public:
    Person()
    {
        age = 0;
    }
    Person(string name, string address, int age)
    {
        this->name = name;
        this->address = address;
        this->age = age;
    }
};

class Employee : public Person
{
private:
    int id;
    int workingDay;
    double rateSallary;

public:
    Employee()
    {
        this->id = 1;
        this->workingDay = 0;
        this->rateSallary = 1.0;
    }

    Employee(int id, int workingDay, double rateSalary, string name, string address, int age) : Person(name, address, age)
    {
        this->id = 1;
        this->workingDay = 0;
        this->rateSallary = 1.0;
    }
};
class EmployeeManager
{
private:
    Employee arrEmp[10];

public:
    void addEmployee(Employee e)
    {
    }
};

int main()
{
    Employee em(1, 23, 35000, "Dong", "TPHCM", 35);
    EmployeeManager e;
    e.addEmployee(em);
}
