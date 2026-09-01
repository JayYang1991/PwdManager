package com.pwdmanager.app.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import com.pwdmanager.app.R;
import com.pwdmanager.app.model.PasswordItem;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PasswordAdapter extends RecyclerView.Adapter<PasswordAdapter.ViewHolder> {

    public interface OnItemActionListener {
        void onEdit(PasswordItem item);
        void onDelete(PasswordItem item);
    }

    private final Context context;
    private final List<PasswordItem> items = new ArrayList<>();
    private final Set<String> revealedPasswordIds = new HashSet<>();
    private final OnItemActionListener listener;

    public PasswordAdapter(Context context, OnItemActionListener listener) {
        this.context = context;
        this.listener = listener;
    }

    public void updateData(List<PasswordItem> newItems) {
        items.clear();
        revealedPasswordIds.clear();
        if (newItems != null) {
            items.addAll(newItems);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_password, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        PasswordItem item = items.get(position);

        holder.tvName.setText(item.getName());
        
        if (item.getUrl() != null && !item.getUrl().isEmpty()) {
            holder.tvUrl.setVisibility(View.VISIBLE);
            holder.tvUrl.setText(item.getUrl());
        } else {
            holder.tvUrl.setVisibility(View.GONE);
        }

        holder.tvUsername.setText(item.getUsername().isEmpty() ? "(未填写)" : item.getUsername());

        boolean isRevealed = revealedPasswordIds.contains(item.getId());
        if (isRevealed) {
            holder.tvPassword.setText(item.getPassword().isEmpty() ? "(空密码)" : item.getPassword());
            holder.btnTogglePassword.setImageResource(android.R.drawable.ic_menu_close_clear_cancel);
        } else {
            holder.tvPassword.setText("••••••••••••");
            holder.btnTogglePassword.setImageResource(android.R.drawable.ic_menu_view);
        }

        holder.btnTogglePassword.setOnClickListener(v -> {
            if (revealedPasswordIds.contains(item.getId())) {
                revealedPasswordIds.remove(item.getId());
            } else {
                revealedPasswordIds.add(item.getId());
            }
            notifyItemChanged(holder.getAdapterPosition());
        });

        holder.btnCopyUsername.setOnClickListener(v -> {
            copyToClipboard("Username", item.getUsername());
            Toast.makeText(context, "已复制账号", Toast.LENGTH_SHORT).show();
        });

        holder.btnCopyPassword.setOnClickListener(v -> {
            copyToClipboard("Password", item.getPassword());
            Toast.makeText(context, "已复制密码到剪贴板", Toast.LENGTH_SHORT).show();
        });

        if (item.getNotes() != null && !item.getNotes().trim().isEmpty()) {
            holder.tvNotes.setVisibility(View.VISIBLE);
            holder.tvNotes.setText("备注: " + item.getNotes());
        } else {
            holder.tvNotes.setVisibility(View.GONE);
        }

        holder.btnEdit.setOnClickListener(v -> {
            if (listener != null) listener.onEdit(item);
        });

        holder.btnDelete.setOnClickListener(v -> {
            if (listener != null) listener.onDelete(item);
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    private void copyToClipboard(String label, String text) {
        ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(label, text);
        if (clipboard != null) {
            clipboard.setPrimaryClip(clip);
        }
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvName, tvUrl, tvUsername, tvPassword, tvNotes;
        ImageButton btnTogglePassword, btnCopyPassword, btnCopyUsername, btnEdit, btnDelete;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvName = itemView.findViewById(R.id.tvName);
            tvUrl = itemView.findViewById(R.id.tvUrl);
            tvUsername = itemView.findViewById(R.id.tvUsername);
            tvPassword = itemView.findViewById(R.id.tvPassword);
            tvNotes = itemView.findViewById(R.id.tvNotes);
            btnTogglePassword = itemView.findViewById(R.id.btnTogglePassword);
            btnCopyPassword = itemView.findViewById(R.id.btnCopyPassword);
            btnCopyUsername = itemView.findViewById(R.id.btnCopyUsername);
            btnEdit = itemView.findViewById(R.id.btnEdit);
            btnDelete = itemView.findViewById(R.id.btnDelete);
        }
    }
}
