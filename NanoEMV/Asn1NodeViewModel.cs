using System.Collections.ObjectModel;
using System.ComponentModel;

namespace NanoEMV
{

    public class Asn1NodeViewModel : INotifyPropertyChanged
    {
        private byte[] _asn1Data;
        private byte[] _tag;
        private byte[] _value;  // Added this

        public byte[] Tag
        {
            get { return _tag; }
            set
            {
                _tag = value;
                OnPropertyChanged("Tag");
            }
        }
        public void ClearChildren()
        {
            Children.Clear();
        }

        public byte[] Asn1Data
        {
            get { return _asn1Data; }
            set
            {
                _asn1Data = value;
                OnPropertyChanged("Asn1Data");
            }
        }

        public byte[] Value  // Added this
        {
            get { return _value; }
            set
            {
                _value = value;
                OnPropertyChanged("Value");
            }
        }

        public Asn1NodeViewModel(string name)
        {
            Name = name;
            Children = new ObservableCollection<Asn1NodeViewModel>();
        }

        public string Name { get; set; }
        public ObservableCollection<Asn1NodeViewModel> Children { get; set; }


        public event PropertyChangedEventHandler PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
