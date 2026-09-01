package com.pwdmanager.app.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
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
    private final OnItemActionListener listener;
    private final List<PasswordItem> items = new ArrayList<>();
    private final Set<String> revealedPasswordIds = new HashSet<>();

    public PasswordAdapter(Context context, OnItemActionListener listener) {
        this.context = context;
        this.listener = listener;
    }

    public void updateData(List<PasswordItem> newItems) {
        items.clear();
        if (newItems != null) {
            items.addAll(newItems);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(context).inflate(R.layout.item_password, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        PasswordItem item = items.get(position);

        holder.tvName.setText(item.getName());

        if (item.getUrl() != null && !item.getUrl().trim().isEmpty()) {
            holder.tvUrl.setVisibility(View.VISIBLE);
            holder.tvUrl.setText(item.getUrl());
            holder.tvUrl.setOnClickListener(v -> {
                try {
                    String u = item.getUrl().trim();
                    if (!u.startsWith("http://") && !u.startsWith("https://")) {
                        u = "https://" + u;
                    }
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(u));
                    context.startActivity(intent);
                } catch (Exception e) {
                    Toast.makeText(context, "无法打开网址: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
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
            copyToClipboard("Username", item.getUsername(), false);
        });

        holder.btnCopyPassword.setOnClickListener(v -> {
            copyToClipboard("Password", item.getPassword(), true);
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

    private void copyToClipboard(String label, String text, boolean isSensitive) {
        ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) return;
        ClipData clip = ClipData.newPlainText(label, text);
        if (isSensitive && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            android.os.PersistableBundle bundle = new android.os.PersistableBundle();
            bundle.putBoolean("android.content.extra.IS_SENSITIVE", true);
            clip.getDescription().setExtras(bundle);
        }
        clipboard.setPrimaryClip(clip);

        if (isSensitive) {
            Toast.makeText(context, "密码已复制，30秒后将自动从剪贴板清除", Toast.LENGTH_SHORT).show();
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                try {
                    ClipData current = clipboard.getPrimaryClip();
                    if (current != null && current.getItemCount() > 0) {
                        CharSequence currentText = current.getItemAt(0).getText();
                        if (text != null && text.equals(currentText != null ? currentText.toString() : "")) {
                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                                clipboard.clearPrimaryClip();
                            } else {
                                clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }, 30000);
        } else {
            Toast.makeText(context, "已复制账号", Toast.LENGTH_SHORT).show();
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
