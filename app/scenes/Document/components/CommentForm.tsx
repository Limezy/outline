import { m } from "framer-motion";
import { action } from "mobx";
import { observer } from "mobx-react";
import * as React from "react";
import { useTranslation } from "react-i18next";
import { CommentValidation } from "@shared/validations";
import Comment from "~/models/Comment";
import Avatar from "~/components/Avatar";
import ButtonSmall from "~/components/ButtonSmall";
import { useDocumentContext } from "~/components/DocumentContext";
import Flex from "~/components/Flex";
import type { Editor as SharedEditor } from "~/editor";
import useCurrentUser from "~/hooks/useCurrentUser";
import useOnClickOutside from "~/hooks/useOnClickOutside";
import usePersistedState from "~/hooks/usePersistedState";
import useStores from "~/hooks/useStores";
import useToasts from "~/hooks/useToasts";
import CommentEditor from "./CommentEditor";
import { Bubble } from "./CommentThreadItem";

type Props = {
  /** The document that the comment will be associated with */
  documentId: string;
  /** The comment thread that the comment will be associated with */
  thread?: Comment;
  /** Placeholder text to display in the editor */
  placeholder?: string;
  /** Whether to focus the editor on mount */
  autoFocus?: boolean;
  /** Whether to render the comment form as standalone, rather than as a reply  */
  standalone?: boolean;
  /** Whether to animate the comment form in and out */
  animatePresence?: boolean;
  /** The text direction of the editor */
  dir?: "rtl" | "ltr";
  /** Callback when the user is typing in the editor */
  onTyping?: () => void;
  /** Callback when the editor is focused */
  onFocus?: () => void;
  /** Callback when the editor is blurred */
  onBlur?: () => void;
  /** Callback when the editor is clicked outside of */
  onClickOutside?: (event: MouseEvent | TouchEvent) => void;
};

function CommentForm({
  documentId,
  thread,
  onTyping,
  onFocus,
  onBlur,
  onClickOutside,
  autoFocus,
  standalone,
  placeholder,
  animatePresence,
  dir,
  ...rest
}: Props) {
  const { editor } = useDocumentContext();
  const [data, setData] = usePersistedState<Record<string, any> | undefined>(
    `draft-${documentId}-${thread?.id ?? "new"}`,
    undefined
  );
  const formRef = React.useRef<HTMLFormElement>(null);
  const editorRef = React.useRef<SharedEditor>(null);
  const [forceRender, setForceRender] = React.useState(0);
  const [inputFocused, setInputFocused] = React.useState(false);
  const { t } = useTranslation();
  const { showToast } = useToasts();
  const { comments } = useStores();
  const user = useCurrentUser();

  useOnClickOutside(formRef, () => {
    const isEmpty = editorRef.current?.isEmpty() ?? true;

    if (isEmpty && thread?.isNew) {
      if (thread.id) {
        editor?.removeComment(thread.id);
      }
      thread.delete();
    }
  });

  const handleCreateComment = action(async (event: React.FormEvent) => {
    event.preventDefault();

    setData(undefined);
    setForceRender((s) => ++s);

    const comment =
      thread ??
      new Comment(
        {
          documentId,
          data,
        },
        comments
      );

    comment
      .save({
        documentId,
        data,
      })
      .catch(() => {
        comment.isNew = true;
        showToast(t("Error creating comment"), { type: "error" });
      });

    // optimistically update the comment model
    comment.isNew = false;
    comment.createdBy = user;
  });

  const handleCreateReply = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!data) {
      return;
    }

    setData(undefined);
    setForceRender((s) => ++s);

    try {
      await comments.save({
        parentCommentId: thread?.id,
        documentId,
        data,
      });
    } catch (error) {
      showToast(t("Error creating comment"), { type: "error" });
    }
  };

  const handleChange = (
    value: (asString: boolean, trim: boolean) => Record<string, any>
  ) => {
    setData(value(false, true));
    onTyping?.();
  };

  const handleSave = () => {
    formRef.current?.dispatchEvent(
      new Event("submit", { cancelable: true, bubbles: true })
    );
  };

  const handleClickPadding = () => {
    if (editorRef.current?.isBlurred) {
      editorRef.current?.focusAtStart();
    }
  };

  const handleCancel = () => {
    setData(undefined);
    setForceRender((s) => ++s);
  };

  const handleFocus = () => {
    onFocus?.();
    setInputFocused(true);
  };

  const handleBlur = () => {
    onBlur?.();
    setInputFocused(false);
  };

  // Focus the editor when it's a new comment just mounted, after a delay as the
  // editor is mounted within a fade transition.
  React.useEffect(() => {
    setTimeout(() => {
      if (autoFocus) {
        editorRef.current?.focusAtStart();
      }
    }, 0);
  }, [autoFocus]);

  const presence = animatePresence
    ? {
        initial: {
          opacity: 0,
          translateY: 100,
        },
        animate: {
          opacity: 1,
          translateY: 0,
          transition: {
            type: "spring",
            bounce: 0.1,
          },
        },
        exit: {
          opacity: 0,
          translateY: 100,
          scale: 0.98,
        },
      }
    : {};

  return (
    <m.form
      ref={formRef}
      onSubmit={thread?.isNew ? handleCreateComment : handleCreateReply}
      {...presence}
      {...rest}
    >
      <Flex gap={8} align="flex-start" reverse={dir === "rtl"}>
        <Avatar model={user} size={24} style={{ marginTop: 8 }} />
        <Bubble
          gap={10}
          onClick={handleClickPadding}
          $lastOfThread
          $firstOfAuthor
          $firstOfThread={standalone}
          column
        >
          <CommentEditor
            key={`${forceRender}`}
            ref={editorRef}
            onChange={handleChange}
            onSave={handleSave}
            onFocus={handleFocus}
            onBlur={handleBlur}
            maxLength={CommentValidation.maxLength}
            placeholder={
              placeholder ||
              // isNew is only the case for comments that exist in draft state,
              // they are marks in the document, but not yet saved to the db.
              (thread?.isNew
                ? `${t("Add a comment")}…`
                : `${t("Add a reply")}…`)
            }
          />

          {inputFocused && (
            <Flex justify={dir === "rtl" ? "flex-end" : "flex-start"} gap={8}>
              <ButtonSmall type="submit" borderOnHover>
                {thread && !thread.isNew ? t("Reply") : t("Post")}
              </ButtonSmall>
              <ButtonSmall onClick={handleCancel} neutral borderOnHover>
                {t("Cancel")}
              </ButtonSmall>
            </Flex>
          )}
        </Bubble>
      </Flex>
    </m.form>
  );
}

export default observer(CommentForm);
