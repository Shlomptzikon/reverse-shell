import random

class DHE:
    def __init__(self, n:int, g:int = 5, e:int = None):
        self.n = n
        self.g = g
        if e is None:
            self.e = random.randint(2,n-2)
        else:
            self.e = e

    def send(self):
        return pow(self.g,self.e,self.n)

    def receive(self,value:int):
        return pow(value, self.e, self.n)



def main():
    dhe1 = DHE(831692804305798069183170825221)
    dhe2 = DHE(831692804305798069183170825221)
    print(f"what dh1 got:{dhe1.receive(dhe2.send())}")
    print(f"what dh2 got:{dhe2.receive(dhe1.send())}")



if __name__ == '__main__':
    main()
