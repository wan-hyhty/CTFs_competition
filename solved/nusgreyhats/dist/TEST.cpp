#include <iostream>
using namespace std;

// parent class
class Shape
{
protected:
    string color;

    // constructor
public:
    Shape()
    {
        color = "Blue";
    };
    Shape(string color)
    {
        this->color = color;
    };
    // neu muon ma doi tuong da hinh goi xuong lop con thi ta dung virtual
    virtual int getArea() = 0;
};
// subclass
class Rectangle : public Shape
{
private:
    int width, height;

public:
    Rectangle()
    {
        this->width = 0;
        this->height = 0;
    }

    Rectangle(int width = 0, int height = 0)
    {
        this->width = width;
        this->height = height;
    }

    Rectangle(int width = 0, int height = 0, string color = "Green") : Shape(color)
    {
        this->width = width;
        this->height = height;
    }

    // getters
    string getColor()
    {
        return this->color;
    }
    int getWidth()
    {
        return this->width;
    }
    int getHeight()
    {
        return this->height;
    }
    // setters

    void setColor(string color)
    {
        this->color = color;
    }
    void setWidth(int width)
    {
        this->width = width;
    }
    void setHeight(int height)
    {
        this->height = height;
    }

    int getArea()
    {
        return height * width;
    }
};

class Circle : public Shape
{
private:
    double radius;

public:
    Circle()
    {
        this->radius = 1.0;
    }
    Circle(double radius)
    {
        this->radius = radius;
    }
    int getArea()
    {
        return 3.14159 * radius * radius;
    }
};

int main()
{
    // bieu dien da hinh:
    Shape *shape;
    Rectangle r(100, 45, "White");
    Circle c(350.5);

    // luu dia chi cua hinh chu nhat r
    shape = &r;
    // goi ham getArea
    int area = shape->getArea();

    cout << r.getColor();
    cout << "Dien tich cua hinh tron la: " << area;

    cout << " " << endl;
    return 0;
}
