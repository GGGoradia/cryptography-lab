#include<iostream>
#include<algorithm>
#include<string>
#include<vector>
using namespace std;
bool uppercase(char a){
  return a>='A'&&a<='Z';
}
bool lowercase(char a){
  return a>='a'&&a<='z';
}
void caesar(const char*string,vector<char> &strino,int k){
  for(int i=0;string[i]!='\0';i++){
    if(uppercase(string[i])){
      strino[i]=(string[i]-'A'+k)%26+'A';
    }
    else if (lowercase(string[i])){
      strino[i]=(string[i]-'a'+k)%26+'a';
    }
    else{
      strino[i]=string[i];
    }
  }
}
int main(){
  int k;
  string pt;
  cout<<"Enter the plain text:";
  cin>>pt;
  vector <char> ct(pt.size(),'a');
  cout<<"Enter the key: ";
  cin>>k;
  caesar(pt.c_str(),ct,k);
  cout<<"Cipher text: ";
  for(auto i:ct){
    cout<<i;
  }
  return 0;
}