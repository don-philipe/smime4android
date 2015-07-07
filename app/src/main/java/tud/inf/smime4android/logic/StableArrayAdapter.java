package tud.inf.smime4android.logic;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.ArrayList;

import tud.inf.smime4android.R;

/**
 * Created by Marco on 07.07.2015.
 */
public class StableArrayAdapter extends ArrayAdapter<String> {
    private final Context context;
    private final ArrayList<String> values;

    public StableArrayAdapter(Context context, ArrayList<String> values) {
        super(context, -1, values);
        this.context = context;
        this.values = values;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        LayoutInflater inflater = (LayoutInflater) context
                .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View rowView = inflater.inflate(R.layout.certificates_listivew_item, parent, false);
        TextView textView = (TextView) rowView.findViewById(R.id.item_text);
        textView.setText(values.get(position));
        // change the icon for Windows and iPhone
        String s = values.get(position);
        return rowView;
    }
}
