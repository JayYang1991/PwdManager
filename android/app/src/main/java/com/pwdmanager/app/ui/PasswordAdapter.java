package com.pwdmanager.app.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.LinearLayout;
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

    // Curated Cosmic Avatar Gradient Color Pairs
    private static final int[][] AVATAR_GRADIENTS = new int[][] {
        { Color.parseColor("#6366F1"), Color.parseColor("#A855F7") }, // Indigo to Purple
        { Color.parseColor("#3B82F6"), Color.parseColor("#06B6D4") }, // Blue to Cyan
        { Color.parseColor("#EC4899"), Color.parseColor("#8B5CF6") }, // Pink to Violet
        { Color.parseColor("#10B981"), Color.parseColor("#06B6D4") }, // Emerald to Teal
        { Color.parseColor("#F59E0B"), Color.parseColor("#EF4444") }, // Amber to Red
        { Color.parseColor("#8B5CF6"), Color.parseColor("#D946EF") }, // Violet to Fuchsia
        { Color.parseColor("#14B8A6"), Color.parseColor("#3B82F6") }, // Teal to Blue
        { Color.parseColor("#F43F5E"), Color.parseColor("#FB923C") }, // Rose to Orange
        { Color.parseColor("#0284C7"), Color.parseColor("#6366F1") }, // Sky to Indigo
        { Color.parseColor("#7C3AED"), Color.parseColor("#DB2777") }, // Purple to Pink
    };

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

        String name = item.getName() != null ? item.getName().trim() : "";
        holder.tvName.setText(name.isEmpty() ? "未命名应用" : name);

        // 1. Dynamic Vibrant Avatar Badge
        String initial = "✦";
        if (!name.isEmpty()) {
            initial = name.substring(0, 1).toUpperCase();
        }
        holder.tvAvatarText.setText(initial);

        int hash = Math.abs(name.hashCode());
        int[] gradientColors = AVATAR_GRADIENTS[hash % AVATAR_GRADIENTS.length];
        GradientDrawable avatarBg = new GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            gradientColors
        );
        avatarBg.setCornerRadius(28f);
        holder.layoutAvatar.setBackground(avatarBg);

        // 2. Global Version Badge
        holder.tvVersionBadge.setText("v" + item.getVersion());

        // 3. Website URL
        if (item.getUrl() != null && !item.getUrl().trim().isEmpty()) {
            holder.layoutUrl.setVisibility(View.VISIBLE);
            holder.tvUrl.setText(item.getUrl().trim());
            holder.layoutUrl.setOnClickListener(v -> {
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
            holder.layoutUrl.setVisibility(View.GONE);
        }

        // 4. Username
        String u = item.getUsername();
        holder.tvUsername.setText((u == null || u.trim().isEmpty()) ? "(未填写)" : u);

        // 5. Password Mask & Reveal
        boolean isRevealed = revealedPasswordIds.contains(item.getId());
        String p = item.getPassword();
        if (isRevealed) {
            holder.tvPassword.setText((p == null || p.isEmpty()) ? "(空密码)" : p);
            holder.btnTogglePassword.setImageResource(R.drawable.ic_eye_off_vector);
        } else {
            holder.tvPassword.setText("••••••••••••");
            holder.btnTogglePassword.setImageResource(R.drawable.ic_eye_vector);
        }

        holder.btnTogglePassword.setOnClickListener(v -> {
            if (revealedPasswordIds.contains(item.getId())) {
                revealedPasswordIds.remove(item.getId());
            } else {
                revealedPasswordIds.add(item.getId());
            }
            int pos = holder.getBindingAdapterPosition();
            if (pos != RecyclerView.NO_POSITION) {
                notifyItemChanged(pos);
            }
        });

        // 6. Copy Actions
        holder.btnCopyUsername.setOnClickListener(v -> {
            copyToClipboard("Username", item.getUsername(), false);
        });

        holder.btnCopyPassword.setOnClickListener(v -> {
            copyToClipboard("Password", item.getPassword(), true);
        });

        // 7. Notes
        if (item.getNotes() != null && !item.getNotes().trim().isEmpty()) {
            holder.layoutNotes.setVisibility(View.VISIBLE);
            holder.tvNotes.setText("备注: " + item.getNotes().trim());
        } else {
            holder.layoutNotes.setVisibility(View.GONE);
        }

        // 8. Edit and Delete Handlers
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
        if (text == null || text.isEmpty()) {
            Toast.makeText(context, "内容为空", Toast.LENGTH_SHORT).show();
            return;
        }
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
            Toast.makeText(context, "🔐 密码已安全复制，30秒后将从剪贴板自动清除", Toast.LENGTH_SHORT).show();
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                try {
                    ClipData current = clipboard.getPrimaryClip();
                    if (current != null && current.getItemCount() > 0) {
                        CharSequence currentText = current.getItemAt(0).getText();
                        if (text.equals(currentText != null ? currentText.toString() : "")) {
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
            Toast.makeText(context, "📋 已复制账号到剪贴板", Toast.LENGTH_SHORT).show();
        }
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        FrameLayout layoutAvatar;
        TextView tvAvatarText, tvName, tvVersionBadge, tvUrl, tvUsername, tvPassword, tvNotes;
        LinearLayout layoutUrl, layoutNotes;
        ImageButton btnTogglePassword, btnCopyPassword, btnCopyUsername, btnEdit, btnDelete;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);
            layoutAvatar = itemView.findViewById(R.id.layoutAvatar);
            tvAvatarText = itemView.findViewById(R.id.tvAvatarText);
            tvName = itemView.findViewById(R.id.tvName);
            tvVersionBadge = itemView.findViewById(R.id.tvVersionBadge);
            layoutUrl = itemView.findViewById(R.id.layoutUrl);
            tvUrl = itemView.findViewById(R.id.tvUrl);
            tvUsername = itemView.findViewById(R.id.tvUsername);
            tvPassword = itemView.findViewById(R.id.tvPassword);
            layoutNotes = itemView.findViewById(R.id.layoutNotes);
            tvNotes = itemView.findViewById(R.id.tvNotes);
            btnTogglePassword = itemView.findViewById(R.id.btnTogglePassword);
            btnCopyPassword = itemView.findViewById(R.id.btnCopyPassword);
            btnCopyUsername = itemView.findViewById(R.id.btnCopyUsername);
            btnEdit = itemView.findViewById(R.id.btnEdit);
            btnDelete = itemView.findViewById(R.id.btnDelete);
        }
    }
}
