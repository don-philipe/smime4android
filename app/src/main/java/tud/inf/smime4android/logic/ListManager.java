package tud.inf.smime4android.logic;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Marco on 09.12.2016.
 */

public class ListManager {

    private static List<String> keyAliases;

    public ListManager(){
        keyAliases = new ArrayList<String>();
    }

    public int getSize(){
        return keyAliases.size();
    }

    public void addElement(String s){
        keyAliases.add(s);
    }

    public void clearList(){
        keyAliases.clear();
    }

    public String getElement(int i){
        return keyAliases.get(i);
    }
}
